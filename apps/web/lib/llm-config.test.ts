import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createSecretKey,
  encryptSecret,
  parseEnvelope,
  serializeEnvelope,
  SecretEncryptionError,
  type SecretKey
} from "./encryption";
import { LlmDestinationError } from "./llm-key-store";

const { findUnique, getEnv } = vi.hoisted(() => ({ findUnique: vi.fn(), getEnv: vi.fn() }));

vi.mock("@paper-viewer/db", () => ({ prisma: { llmConfig: { findUnique } } }));
vi.mock("@/lib/env", () => ({ getEnv }));

const { resolveLlmConfig } = await import("./llm-config");

const ACTIVE_MATERIAL = "active-key-material-at-least-32-bytes";
const BASE_URL = "https://db.example/v1";

function activeKey(): SecretKey {
  return createSecretKey(2, ACTIVE_MATERIAL);
}

function encrypted(plaintext: string): string {
  return serializeEnvelope(encryptSecret(plaintext, activeKey()));
}

function row(overrides: Record<string, unknown> = {}) {
  return {
    workspaceId: "ws-1",
    baseUrl: BASE_URL,
    model: "db-model",
    apiKey: "",
    apiKeyEnvelope: encrypted("sk-resolved-key"),
    apiKeyDestination: BASE_URL,
    ...overrides
  };
}

beforeEach(() => {
  getEnv.mockReturnValue({
    LLM_KEY_ENCRYPTION_SECRET: ACTIVE_MATERIAL,
    LLM_KEY_ENCRYPTION_VERSION: 2,
    LLM_API_KEY: undefined,
    LLM_BASE_URL: "https://env.example/v1",
    LLM_MODEL: "env-model"
  });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("resolveLlmConfig", () => {
  it("decrypts the bound envelope and returns a usable runtime config", async () => {
    findUnique.mockResolvedValue(row());

    await expect(resolveLlmConfig("ws-1")).resolves.toEqual({
      baseUrl: BASE_URL,
      model: "db-model",
      apiKey: "sk-resolved-key"
    });
  });

  it("still resolves a not-yet-migrated but bound plaintext row", async () => {
    findUnique.mockResolvedValue(row({ apiKey: "sk-legacy-key", apiKeyEnvelope: null }));

    await expect(resolveLlmConfig("ws-1")).resolves.toMatchObject({ apiKey: "sk-legacy-key" });
  });

  it("fails closed when a stored envelope cannot be decrypted", async () => {
    const envelope = parseEnvelope(encrypted("sk-real"));
    const first = envelope.ct.charAt(0);
    findUnique.mockResolvedValue(
      row({
        apiKey: "sk-stale-plaintext",
        apiKeyEnvelope: serializeEnvelope({ ...envelope, ct: (first === "A" ? "B" : "A") + envelope.ct.slice(1) })
      })
    );

    await expect(resolveLlmConfig("ws-1")).rejects.toThrow(SecretEncryptionError);
  });

  it("refuses to use a bound key after the stored baseUrl changes", async () => {
    findUnique.mockResolvedValue(row({ baseUrl: "https://attacker.example/v1" }));

    await expect(resolveLlmConfig("ws-1")).rejects.toThrow(LlmDestinationError);
  });

  it("refuses an unbound legacy credential", async () => {
    findUnique.mockResolvedValue(row({ apiKey: "sk-unbound", apiKeyEnvelope: null, apiKeyDestination: null }));

    await expect(resolveLlmConfig("ws-1")).rejects.toThrow(LlmDestinationError);
  });

  it("keeps the env fallback unchanged when there is no DB row", async () => {
    findUnique.mockResolvedValue(null);
    getEnv.mockReturnValue({
      LLM_KEY_ENCRYPTION_SECRET: ACTIVE_MATERIAL,
      LLM_KEY_ENCRYPTION_VERSION: 2,
      LLM_API_KEY: "sk-env-key",
      LLM_BASE_URL: "https://env.example/v1",
      LLM_MODEL: "env-model"
    });

    await expect(resolveLlmConfig("ws-1")).resolves.toEqual({
      baseUrl: "https://env.example/v1",
      model: "env-model",
      apiKey: "sk-env-key"
    });
  });

  it("throws an explicit error when neither DB nor env has a key", async () => {
    findUnique.mockResolvedValue(null);
    await expect(resolveLlmConfig("ws-1")).rejects.toThrow(/LLM not configured/);
  });
});
