/**
 * P1-T02 — integration of the P1-T01 envelope helper into the LLM config
 * lifecycle (ADR-013 / SECURITY_DESIGN.md §1).
 *
 * Responsibilities:
 *   - Encrypt an API key into a versioned envelope before it reaches Postgres.
 *   - Decrypt it on the server only, via a version-aware key lookup.
 *   - Bind each key to the exact normalized destination approved at save time;
 *     a key is never authorized for a merely similar or newly configured host.
 *   - Reconcile legacy plaintext rows through an explicit, restartable,
 *     double-encryption-safe migration (no plaintext value is ever logged).
 *   - Re-encrypt historical key versions during rotation.
 *
 * All crypto failures surface as generic `SecretEncryptionError`s: callers must
 * propagate them (fail closed) and must never fall back to a plaintext or
 * empty key.
 */

import { prisma } from "@paper-viewer/db";
import {
  createSecretKey,
  decryptSecret,
  encryptSecret,
  getActiveEncryptionKey,
  parseEnvelope,
  serializeEnvelope,
  type SecretKey,
  type SecretKeyLookup
} from "./encryption";

/** Minimal structural view of a persisted LLM credential. */
export type StoredLlmKey = {
  apiKey: string;
  apiKeyEnvelope: string | null;
  /** Destination approved when the key was saved; absent/Null ⇒ unbound legacy row. */
  apiKeyDestination?: string | null;
};

/** Raised when a stored key would be sent to a destination other than the one it was saved for. */
export class LlmDestinationError extends Error {
  constructor() {
    super("Stored LLM API key is not authorized for this destination.");
    this.name = "LlmDestinationError";
  }
}

/**
 * Canonical destination identity: scheme, host (including a non-default port)
 * and base path. Credentials in the URL are rejected. Query/hash are not part
 * of a provider destination and are ignored.
 */
export function normalizeLlmDestination(baseUrl: string): string {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new LlmDestinationError();
  }
  if ((url.protocol !== "https:" && url.protocol !== "http:") || url.username || url.password) {
    throw new LlmDestinationError();
  }
  const path = url.pathname.replace(/\/+$/, "");
  return `${url.protocol}//${url.host}${path}`;
}

/**
 * Fail closed unless the row has an explicit binding that matches the exact
 * destination being used. Unbound legacy rows are never authorized: their key
 * must be re-entered (with a base URL) before it can be sent anywhere.
 */
export function assertLlmDestination(row: StoredLlmKey, requestedBaseUrl: string): void {
  const bound = row.apiKeyDestination;
  if (!bound) throw new LlmDestinationError();
  if (normalizeLlmDestination(bound) !== normalizeLlmDestination(requestedBaseUrl)) {
    throw new LlmDestinationError();
  }
}

/** `LLM_KEY_ENCRYPTION_SECRET_<N>` supplies historical KEK version N. */
const HISTORICAL_KEY_ENV = /^LLM_KEY_ENCRYPTION_SECRET_(\d+)$/;

/** Build a version-aware lookup from an explicit set of keys (active wins). */
export function buildSecretKeyLookup(keys: readonly SecretKey[]): SecretKeyLookup {
  const keyring = new Map<number, SecretKey>();
  for (const key of keys) keyring.set(key.version, key);
  return (version) => keyring.get(version);
}

/**
 * Server keyring: the active KEK from getEnv() plus every historical KEK
 * published as `LLM_KEY_ENCRYPTION_SECRET_<version>`. Historical keys let us
 * decrypt old envelopes while rotation is in progress.
 */
export function getServerKeyLookup(env: Record<string, string | undefined> = process.env): SecretKeyLookup {
  const historical: SecretKey[] = [];
  for (const [name, value] of Object.entries(env)) {
    const match = HISTORICAL_KEY_ENV.exec(name);
    const version = match?.[1];
    if (version && value) historical.push(createSecretKey(Number(version), value));
  }
  // Insert last so the active version wins if it is also declared historically.
  return buildSecretKeyLookup([...historical, getActiveEncryptionKey()]);
}

/** Encrypt a plaintext key into the serialized envelope stored in Postgres. */
export function encryptApiKey(plaintext: string, key: SecretKey = getActiveEncryptionKey()): string {
  return serializeEnvelope(encryptSecret(plaintext, key));
}

/** Decrypt a stored envelope using the server keyring (or an injected lookup). */
export function decryptApiKey(envelope: string, lookup: SecretKeyLookup = getServerKeyLookup()): string {
  return decryptSecret(envelope, lookup);
}

/**
 * Resolve the plaintext key from a DB row.
 *
 * Encrypted rows are decrypted only here, on the server. If an envelope exists
 * but cannot be decrypted, the error propagates — we never fall back to the
 * legacy field, to an empty string, or to a different provider. A legacy row
 * (envelope not yet backfilled) can still resolve via its plaintext column, but
 * only after a destination binding exists — unbound rows are rejected by the
 * outbound callers via `assertLlmDestination`.
 *
 * Callers that will USE the key for an outbound request must first call
 * `assertLlmDestination(row, destination)`; masking-only reads need not.
 */
export function readStoredApiKey(row: StoredLlmKey, lookup?: SecretKeyLookup): string {
  if (row.apiKeyEnvelope) {
    return decryptApiKey(row.apiKeyEnvelope, lookup ?? getServerKeyLookup());
  }
  return row.apiKey;
}

// ---------------------------------------------------------------------------
// Explicit data migration (legacy plaintext → envelope)
// ---------------------------------------------------------------------------

/** Minimal Prisma surface needed by the migration; keeps it unit-testable. */
export interface LlmKeyMigrationClient {
  llmConfig: {
    findMany(args: {
      where: { apiKeyEnvelope: null; apiKey: { not: "" } };
      select: { id: true; apiKey: true };
    }): Promise<Array<{ id: string; apiKey: string }>>;
    updateMany(args: {
      // Guard without embedding the plaintext value in query args: Prisma can
      // include failed query parameters in error logs.
      where: { id: string; apiKeyEnvelope: null; apiKey: { not: "" } };
      data: { apiKey: ""; apiKeyEnvelope: string };
    }): Promise<{ count: number }>;
  };
}

export interface LlmKeyMigrationSummary {
  scanned: number;
  migrated: number;
  /** Row was changed concurrently (already migrated); left untouched. */
  conflicted: number;
  /** Encryption failed; row left untouched for a later, retryable run. */
  failed: number;
}

/**
 * Backfill legacy plaintext keys into envelopes.
 *
 * Safe to run repeatedly: the `where` guard requires `apiKeyEnvelope IS NULL`
 * and a non-empty legacy `apiKey` (without putting that plaintext into query
 * arguments, which Prisma may echo in error logs). Once a row is migrated it
 * no longer matches the initial `findMany`, and a concurrent writer makes
 * `updateMany` return `count = 0` rather than double-encrypting the value.
 * Only aggregate counts are returned — no key value, envelope, or row id is
 * logged or exposed.
 */
export async function migrateLegacyLlmApiKeys(
  client: LlmKeyMigrationClient = prisma as unknown as LlmKeyMigrationClient,
  options: { activeKey?: SecretKey } = {}
): Promise<LlmKeyMigrationSummary> {
  const key = options.activeKey ?? getActiveEncryptionKey();
  const rows = await client.llmConfig.findMany({
    where: { apiKeyEnvelope: null, apiKey: { not: "" } },
    select: { id: true, apiKey: true }
  });

  const summary: LlmKeyMigrationSummary = { scanned: rows.length, migrated: 0, conflicted: 0, failed: 0 };
  for (const row of rows) {
    try {
      const envelope = encryptApiKey(row.apiKey, key);
      const result = await client.llmConfig.updateMany({
        where: { id: row.id, apiKeyEnvelope: null, apiKey: { not: "" } },
        data: { apiKey: "", apiKeyEnvelope: envelope }
      });
      if (result.count === 1) summary.migrated += 1;
      else summary.conflicted += 1;
    } catch {
      // Fail closed: never persist the plaintext we failed to encrypt.
      summary.failed += 1;
    }
  }
  return summary;
}

// ---------------------------------------------------------------------------
// Rotation (re-encrypt historical key versions under the active KEK)
// ---------------------------------------------------------------------------

/** Minimal Prisma surface needed by rotation. */
export interface LlmKeyRotationClient {
  llmConfig: {
    findMany(args: {
      where: { apiKeyEnvelope: { not: null } };
      select: { id: true; apiKeyEnvelope: true };
    }): Promise<Array<{ id: string; apiKeyEnvelope: string | null }>>;
    updateMany(args: {
      where: { id: string; apiKeyEnvelope: string };
      data: { apiKeyEnvelope: string };
    }): Promise<{ count: number }>;
  };
}

export interface LlmKeyRotationSummary {
  scanned: number;
  rotated: number;
  upToDate: number;
  conflicted: number;
  failed: number;
}

/** Re-encrypt envelopes whose `kid` differs from the active key version. */
export async function rotateLlmApiKeys(
  client: LlmKeyRotationClient = prisma as unknown as LlmKeyRotationClient,
  options: { activeKey?: SecretKey; lookup?: SecretKeyLookup } = {}
): Promise<LlmKeyRotationSummary> {
  const activeKey = options.activeKey ?? getActiveEncryptionKey();
  const lookup = options.lookup ?? getServerKeyLookup();
  const rows = await client.llmConfig.findMany({
    where: { apiKeyEnvelope: { not: null } },
    select: { id: true, apiKeyEnvelope: true }
  });

  const summary: LlmKeyRotationSummary = {
    scanned: rows.length,
    rotated: 0,
    upToDate: 0,
    conflicted: 0,
    failed: 0
  };
  for (const row of rows) {
    const envelope = row.apiKeyEnvelope;
    if (!envelope) continue;
    try {
      if (parseEnvelope(envelope).kid === activeKey.version) {
        summary.upToDate += 1;
        continue;
      }
      // Decrypt with the historical key, re-encrypt with the active one. If a
      // historical KEK is missing this throws and the row stays untouched.
      const plaintext = decryptSecret(envelope, lookup);
      const rotated = serializeEnvelope(encryptSecret(plaintext, activeKey));
      const result = await client.llmConfig.updateMany({
        where: { id: row.id, apiKeyEnvelope: envelope },
        data: { apiKeyEnvelope: rotated }
      });
      if (result.count === 1) summary.rotated += 1;
      else summary.conflicted += 1;
    } catch {
      summary.failed += 1;
    }
  }
  return summary;
}
