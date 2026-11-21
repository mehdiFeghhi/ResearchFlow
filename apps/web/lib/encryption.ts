/**
 * Server-only envelope encryption for sensitive application secrets, chiefly
 * the per-workspace LLM API keys stored by `LlmConfig` (ADR-013).
 *
 * Design (see architecture/SECURITY_DESIGN.md §1):
 *   - AES-256-GCM authenticated encryption, 96-bit random nonce per call.
 *   - HKDF-SHA256 derives the 256-bit data key from deployment key material,
 *     domain-separated with fixed salt + info so the same material cannot be
 *     reused for an unrelated purpose.
 *   - A versioned JSON envelope carries all public metadata. That metadata is
 *     fed to GCM as Additional Authenticated Data, so tampering with the
 *     version, algorithm, key version or nonce fails authentication.
 *   - Key version (`kid`) is part of the envelope; decryption accepts either a
 *     single key (which must match `kid`) or a lookup function, so historical
 *     keys can be retained for rotation without changing this module.
 *
 * This module is server-only by construction: it imports `node:crypto`, which
 * cannot be bundled into a browser. Never re-export it from a client module,
 * and never log its inputs or outputs.
 *
 * Operational requirement: retain every historical key until ALL ciphertext
 * encrypted under it has been re-encrypted under the active version. Losing a
 * key makes its ciphertext permanently undecryptable — there is no recovery
 * path and no plaintext fallback by design.
 */

import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
  type BinaryLike
} from "node:crypto";
import { z } from "zod";
import { getEnv } from "./env";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Envelope serialization format. Bump only with an explicit migration plan. */
export const ENVELOPE_FORMAT_VERSION = 1 as const;
/** Authenticated encryption algorithm identifier stored in the envelope. */
export const ENCRYPTION_ALGORITHM = "A256GCM" as const;
/** Key-derivation function identifier stored in the envelope. */
export const KEY_DERIVATION = "HKDF-SHA256" as const;

const NONCE_BYTES = 12; // 96-bit nonce, the GCM standard
const TAG_BYTES = 16;
const DATA_KEY_BYTES = 32; // AES-256
const MIN_KEY_MATERIAL_BYTES = 32;

/** Fixed, application-specific HKDF salt (domain separation across apps). */
const HKDF_SALT = Buffer.from("paper-viewer/secret-encryption/v1/salt", "utf8");
/** Fixed, purpose-specific HKDF info (domain separation across purposes). */
const HKDF_INFO = Buffer.from("paper-viewer/secret-encryption/v1/aes-256-gcm", "utf8");
/** Prefix of the canonical AAD string; also domain-separates the GCM context. */
const AAD_CONTEXT = "paper-viewer.secret-envelope.v1";

// ---------------------------------------------------------------------------
// Errors — deliberately generic: no secrets, internals or crypto diagnostics
// ---------------------------------------------------------------------------

export class SecretEncryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SecretEncryptionError";
  }
}

const ERR = {
  invalidKey: () => new SecretEncryptionError("Invalid encryption key material."),
  missingKey: () => new SecretEncryptionError("No encryption key is available for the encrypted secret."),
  versionMismatch: () => new SecretEncryptionError("Encryption key version does not match the encrypted secret."),
  invalidEnvelope: () => new SecretEncryptionError("Invalid encrypted secret envelope."),
  invalidPlaintext: () => new SecretEncryptionError("A non-empty secret is required."),
  encryptFailed: () => new SecretEncryptionError("Unable to encrypt secret."),
  decryptFailed: () => new SecretEncryptionError("Unable to decrypt encrypted secret."),
  missingConfig: () => new SecretEncryptionError("LLM_KEY_ENCRYPTION_SECRET is not configured.")
} as const;

// ---------------------------------------------------------------------------
// Envelope format & parsing
// ---------------------------------------------------------------------------

/**
 * Wire format (JSON, base64url for all binary fields):
 * {
 *   "v":   1,                       // envelope format version
 *   "alg": "A256GCM",               // authenticated encryption algorithm
 *   "kdf": "HKDF-SHA256",           // key derivation function
 *   "kid": 1,                       // key version (rotation)
 *   "iv":  "<base64url, 12 bytes>", // random nonce
 *   "tag": "<base64url, 16 bytes>", // GCM authentication tag
 *   "ct":  "<base64url, n bytes>"   // ciphertext (UTF-8 plaintext bytes)
 * }
 */
export interface EncryptedEnvelope {
  readonly v: typeof ENVELOPE_FORMAT_VERSION;
  readonly alg: typeof ENCRYPTION_ALGORITHM;
  readonly kdf: typeof KEY_DERIVATION;
  readonly kid: number;
  readonly iv: string;
  readonly tag: string;
  readonly ct: string;
}

const BASE64URL = /^[A-Za-z0-9_-]+$/;

/** Decode a canonical base64url string of an exact byte length, or null. */
function decodeBase64Url(value: string, expectedBytes: number): Buffer | null {
  if (value.length === 0 || !BASE64URL.test(value)) return null;
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== expectedBytes) return null;
  // Reject non-canonical encodings (alternate padding/bit representations).
  if (decoded.toString("base64url") !== value) return null;
  return decoded;
}

const envelopeSchema = z
  .object({
    v: z.literal(ENVELOPE_FORMAT_VERSION),
    alg: z.literal(ENCRYPTION_ALGORITHM),
    kdf: z.literal(KEY_DERIVATION),
    kid: z.number().int().positive(),
    iv: z.string(),
    tag: z.string(),
    ct: z.string()
  })
  .strict();

/** Parse and fully validate an envelope, throwing only generic errors. */
export function parseEnvelope(input: string | EncryptedEnvelope): EncryptedEnvelope {
  let candidate: unknown = input;
  try {
    if (typeof input === "string") {
      candidate = JSON.parse(input) as unknown;
    }
    const parsed = envelopeSchema.parse(candidate);
    if (!decodeBase64Url(parsed.iv, NONCE_BYTES)) throw ERR.invalidEnvelope();
    if (!decodeBase64Url(parsed.tag, TAG_BYTES)) throw ERR.invalidEnvelope();
    // Ciphertext may be empty only if the plaintext was empty, which we never encrypt.
    if (!decodeBase64Url(parsed.ct, Buffer.from(parsed.ct, "base64url").length) || parsed.ct.length === 0) {
      throw ERR.invalidEnvelope();
    }
    return parsed;
  } catch {
    // Collapse every zod/JSON failure into one safe error — no field values or
    // parser diagnostics escape to logs or callers.
    throw ERR.invalidEnvelope();
  }
}

/** Serialize a validated envelope to its stable JSON representation. */
export function serializeEnvelope(envelope: EncryptedEnvelope): string {
  return JSON.stringify(parseEnvelope(envelope));
}

/** Canonical AAD: authenticates the public envelope metadata via GCM. */
function buildAad(envelope: EncryptedEnvelope): Buffer {
  return Buffer.from(
    `${AAD_CONTEXT}|v=${envelope.v}|alg=${envelope.alg}|kdf=${envelope.kdf}|kid=${envelope.kid}|iv=${envelope.iv}`,
    "utf8"
  );
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

/**
 * A validated key: a version number plus raw deployment key material.
 * Construct with `createSecretKey`; do not build this object by hand.
 */
export interface SecretKey {
  readonly version: number;
  readonly material: Buffer;
}

/** Rotation hook: resolve the key for an envelope's `kid` (undefined = none). */
export type SecretKeyLookup = (version: number) => SecretKey | undefined;
/** Decryption accepts one key or a lookup, so old keys remain usable. */
export type SecretKeySource = SecretKey | SecretKeyLookup;

function assertValidKey(key: SecretKey): void {
  if (
    !key ||
    !Number.isInteger(key.version) ||
    key.version < 1 ||
    !Buffer.isBuffer(key.material) ||
    key.material.length < MIN_KEY_MATERIAL_BYTES
  ) {
    throw ERR.invalidKey();
  }
}

/** Validate key material and return an immutable copy. */
export function createSecretKey(version: number, material: string | Buffer): SecretKey {
  const bytes = Buffer.isBuffer(material) ? Buffer.from(material) : Buffer.from(material, "utf8");
  const key: SecretKey = { version, material: bytes };
  assertValidKey(key);
  return key;
}

/**
 * Build the active key from environment configuration. Introduced here only;
 * P1-T02 will wire it into `resolveLlmConfig`. Historical keys for rotation
 * are supplied by the caller via `SecretKeyLookup`.
 */
export function getActiveEncryptionKey(): SecretKey {
  const env = getEnv();
  const secret = env.LLM_KEY_ENCRYPTION_SECRET;
  if (!secret) throw ERR.missingConfig();
  const version = env.LLM_KEY_ENCRYPTION_VERSION ?? 1;
  // Strict validation: no default, no weak/short material.
  return createSecretKey(version, secret);
}

/** HKDF-SHA256 → 256-bit data encryption key, domain-separated. */
function deriveDataKey(key: SecretKey): Buffer {
  assertValidKey(key);
  return Buffer.from(hkdfSync("sha256", key.material as BinaryLike, HKDF_SALT, HKDF_INFO, DATA_KEY_BYTES));
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** Encrypt a non-empty UTF-8 secret into a versioned envelope. */
export function encryptSecret(plaintext: string, key: SecretKey): EncryptedEnvelope {
  if (typeof plaintext !== "string" || plaintext.length === 0) throw ERR.invalidPlaintext();
  assertValidKey(key);

  try {
    const iv = randomBytes(NONCE_BYTES); // fresh CSPRNG nonce every call
    const dataKey = deriveDataKey(key);
    const cipher = createCipheriv("aes-256-gcm", dataKey, iv);
    const envelopeMeta: EncryptedEnvelope = {
      v: ENVELOPE_FORMAT_VERSION,
      alg: ENCRYPTION_ALGORITHM,
      kdf: KEY_DERIVATION,
      kid: key.version,
      iv: iv.toString("base64url"),
      tag: "",
      ct: ""
    };
    cipher.setAAD(buildAad(envelopeMeta));
    const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
    const tag = cipher.getAuthTag();

    return parseEnvelope({
      ...envelopeMeta,
      tag: tag.toString("base64url"),
      ct: ciphertext.toString("base64url")
    });
  } catch (error) {
    if (error instanceof SecretEncryptionError) throw error;
    throw ERR.encryptFailed();
  }
}

/** Decrypt an envelope using a single key or a version-aware key lookup. */
export function decryptSecret(input: string | EncryptedEnvelope, source: SecretKeySource): string {
  const envelope = parseEnvelope(input);

  let key: SecretKey;
  if (typeof source === "function") {
    const resolved = source(envelope.kid);
    if (!resolved) throw ERR.missingKey();
    key = resolved;
  } else {
    key = source;
  }
  assertValidKey(key);
  if (key.version !== envelope.kid) throw ERR.versionMismatch();

  try {
    const iv = decodeBase64Url(envelope.iv, NONCE_BYTES);
    const tag = decodeBase64Url(envelope.tag, TAG_BYTES);
    const ciphertext = decodeBase64Url(envelope.ct, Buffer.from(envelope.ct, "base64url").length);
    if (!iv || !tag || !ciphertext) throw ERR.invalidEnvelope();

    const dataKey = deriveDataKey(key);
    const decipher = createDecipheriv("aes-256-gcm", dataKey, iv);
    decipher.setAAD(buildAad(envelope));
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString("utf8");
  } catch (error) {
    // Authentication failures, bad tags and malformed bytes all collapse here.
    if (error instanceof SecretEncryptionError) throw error;
    throw ERR.decryptFailed();
  }
}
