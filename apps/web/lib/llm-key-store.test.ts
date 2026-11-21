import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createSecretKey,
  decryptSecret,
  encryptSecret,
  parseEnvelope,
  SecretEncryptionError,
  serializeEnvelope,
  type SecretKey
} from "./encryption";
import {
  assertLlmDestination,
  buildSecretKeyLookup,
  decryptApiKey,
  encryptApiKey,
  getServerKeyLookup,
  LlmDestinationError,
  migrateLegacyLlmApiKeys,
  normalizeLlmDestination,
  readStoredApiKey,
  rotateLlmApiKeys,
  type LlmKeyMigrationClient,
  type LlmKeyRotationClient
} from "./llm-key-store";

const { getEnv } = vi.hoisted(() => ({ getEnv: vi.fn() }));
vi.mock("./env", () => ({ getEnv }));

const ACTIVE_MATERIAL = "active-key-material-at-least-32-bytes";
const HISTORIC_MATERIAL = "historic-key-material-at-least-32-bytes";

function key(version: number, material = "test-key-material-"): SecretKey {
  return createSecretKey(version, material.repeat(4));
}

function tamper(envelope: string): string {
  const parsed = parseEnvelope(envelope);
  const first = parsed.ct.charAt(0);
  return serializeEnvelope({ ...parsed, ct: (first === "A" ? "B" : "A") + parsed.ct.slice(1) });
}

type StoredRow = { id: string; apiKey: string; apiKeyEnvelope: string | null };

function migrationFixture(rows: StoredRow[]) {
  const state = rows.map((row) => ({ ...row }));
  const findMany = vi.fn(async () =>
    state
      .filter((row) => row.apiKeyEnvelope === null && row.apiKey !== "")
      .map((row) => ({ id: row.id, apiKey: row.apiKey }))
  );
  const updateMany = vi.fn(async (args: { where: { id: string; apiKey: { not: string } }; data: { apiKey: string; apiKeyEnvelope: string } }) => {
    const row = state.find((candidate) => candidate.id === args.where.id);
    if (!row || row.apiKeyEnvelope !== null || row.apiKey === args.where.apiKey.not) return { count: 0 };
    row.apiKey = args.data.apiKey;
    row.apiKeyEnvelope = args.data.apiKeyEnvelope;
    return { count: 1 };
  });
  return {
    state,
    findMany,
    updateMany,
    client: { llmConfig: { findMany, updateMany } } as unknown as LlmKeyMigrationClient
  };
}

function rotationFixture(rows: StoredRow[]) {
  const state = rows.map((row) => ({ ...row }));
  const findMany = vi.fn(async () =>
    state
      .filter((row) => row.apiKeyEnvelope !== null)
      .map((row) => ({ id: row.id, apiKeyEnvelope: row.apiKeyEnvelope }))
  );
  const updateMany = vi.fn(async (args: { where: { id: string; apiKeyEnvelope: string }; data: { apiKeyEnvelope: string } }) => {
    const row = state.find((candidate) => candidate.id === args.where.id);
    if (!row || row.apiKeyEnvelope !== args.where.apiKeyEnvelope) return { count: 0 };
    row.apiKeyEnvelope = args.data.apiKeyEnvelope;
    return { count: 1 };
  });
  return {
    state,
    findMany,
    updateMany,
    client: { llmConfig: { findMany, updateMany } } as unknown as LlmKeyRotationClient
  };
}

beforeEach(() => {
  getEnv.mockReturnValue({
    LLM_KEY_ENCRYPTION_SECRET: ACTIVE_MATERIAL,
    LLM_KEY_ENCRYPTION_VERSION: 2
  });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("stored LLM key encryption", () => {
  it("encrypts before persistence and decrypts with the matching lookup", () => {
    const k = key(2);
    const plaintext = "sk-store-roundtrip-1234";
    const envelope = encryptApiKey(plaintext, k);

    expect(envelope).not.toContain(plaintext);
    expect(parseEnvelope(envelope).kid).toBe(2);
    expect(decryptApiKey(envelope, buildSecretKeyLookup([k]))).toBe(plaintext);
  });

  it("decrypts a previously encrypted value (version 1 envelope)", () => {
    const legacyKey = key(1, "legacy-key-material-");
    const envelope = serializeEnvelope(encryptSecret("sk-previously-encrypted", legacyKey));

    expect(decryptApiKey(envelope, buildSecretKeyLookup([legacyKey]))).toBe("sk-previously-encrypted");
  });

  it("handles historical key versions through the keyring", () => {
    const v1 = key(1, "rotation-v1-material-");
    const v2 = key(2, "rotation-v2-material-");
    const keyring = buildSecretKeyLookup([v1, v2]);
    const oldEnvelope = encryptApiKey("sk-from-v1", v1);

    expect(decryptApiKey(oldEnvelope, keyring)).toBe("sk-from-v1");

    const rotated = serializeEnvelope(encryptSecret(decryptSecret(oldEnvelope, keyring), v2));
    expect(parseEnvelope(rotated).kid).toBe(2);
    expect(decryptApiKey(rotated, keyring)).toBe("sk-from-v1");
  });

  it("builds the server keyring from the env historical-key pattern", () => {
    const historical = createSecretKey(1, HISTORIC_MATERIAL);
    const lookup = getServerKeyLookup({ LLM_KEY_ENCRYPTION_SECRET_1: HISTORIC_MATERIAL });
    const envelope = encryptApiKey("sk-historic-env", historical);

    // The active env version is 2; decryption must still find version 1.
    expect(decryptApiKey(envelope, lookup)).toBe("sk-historic-env");
    expect(parseEnvelope(encryptApiKey("sk-active", key(2, ACTIVE_MATERIAL))).kid).toBe(2);
  });

  it("fails closed on decryption failure without leaking the plaintext", () => {
    const k = key(2);
    const plaintext = "sk-DO-NOT-LEAK";
    const broken = tamper(encryptApiKey(plaintext, k));

    expect(() => decryptApiKey(broken, buildSecretKeyLookup([k]))).toThrow(SecretEncryptionError);
    try {
      decryptApiKey(broken, buildSecretKeyLookup([k]));
      throw new Error("expected failure");
    } catch (error) {
      expect((error as Error).message).not.toContain(plaintext);
    }
  });

  it("fails closed on encryption failure", () => {
    expect(() => encryptApiKey("sk-x", {} as SecretKey)).toThrow(SecretEncryptionError);
  });

  describe("readStoredApiKey", () => {
    it("decrypts an encrypted row", () => {
      const k = key(2);
      const envelope = encryptApiKey("sk-encrypted-row", k);
      expect(readStoredApiKey({ apiKey: "", apiKeyEnvelope: envelope }, buildSecretKeyLookup([k]))).toBe(
        "sk-encrypted-row"
      );
    });

    it("still resolves a legacy plaintext row", () => {
      expect(readStoredApiKey({ apiKey: "sk-legacy", apiKeyEnvelope: null })).toBe("sk-legacy");
    });

    it("does not fall back to plaintext when an envelope fails to decrypt", () => {
      const k = key(2);
      const broken = tamper(encryptApiKey("sk-real", k));
      expect(() =>
        readStoredApiKey(
          { apiKey: "sk-stale-plaintext", apiKeyEnvelope: broken },
          buildSecretKeyLookup([key(3)])
        )
      ).toThrow(SecretEncryptionError);
    });
  });
});

describe("legacy plaintext migration", () => {
  it("encrypts legacy values, clears the plaintext column, and preserves the key", async () => {
    const active = key(2);
    const fixture = migrationFixture([{ id: "row-1", apiKey: "sk-migrate-me", apiKeyEnvelope: null }]);

    const summary = await migrateLegacyLlmApiKeys(fixture.client, { activeKey: active });

    expect(summary).toEqual({ scanned: 1, migrated: 1, conflicted: 0, failed: 0 });
    const row = fixture.state[0]!;
    expect(row.apiKey).toBe("");
    expect(row.apiKeyEnvelope).not.toContain("sk-migrate-me");
    expect(decryptApiKey(row.apiKeyEnvelope!, buildSecretKeyLookup([active]))).toBe("sk-migrate-me");
    expect(JSON.stringify(fixture.state)).not.toContain("sk-migrate-me");
    // Query arguments are the most likely place a DB error log could leak a key.
    expect(JSON.stringify(fixture.updateMany.mock.calls)).not.toContain("sk-migrate-me");
    expect(JSON.stringify(fixture.findMany.mock.calls)).not.toContain("sk-migrate-me");
  });

  it("is repeatable and never double-encrypts", async () => {
    const active = key(2);
    const fixture = migrationFixture([{ id: "row-1", apiKey: "sk-once", apiKeyEnvelope: null }]);

    await migrateLegacyLlmApiKeys(fixture.client, { activeKey: active });
    const firstEnvelope = fixture.state[0]!.apiKeyEnvelope;
    const second = await migrateLegacyLlmApiKeys(fixture.client, { activeKey: active });

    expect(second).toEqual({ scanned: 0, migrated: 0, conflicted: 0, failed: 0 });
    expect(fixture.state[0]!.apiKeyEnvelope).toBe(firstEnvelope);
  });

  it("skips rows that are already encrypted", async () => {
    const active = key(2);
    const encrypted = encryptApiKey("sk-done", active);
    const fixture = migrationFixture([
      { id: "done", apiKey: "", apiKeyEnvelope: encrypted },
      { id: "legacy", apiKey: "sk-todo", apiKeyEnvelope: null }
    ]);

    const summary = await migrateLegacyLlmApiKeys(fixture.client, { activeKey: active });

    expect(summary.migrated).toBe(1);
    expect(fixture.state[0]!.apiKeyEnvelope).toBe(encrypted);
  });

  it("treats a concurrent write as a conflict instead of double encrypting", async () => {
    const active = key(2);
    const fixture = migrationFixture([{ id: "row-1", apiKey: "sk-concurrent", apiKeyEnvelope: null }]);
    fixture.updateMany.mockResolvedValueOnce({ count: 0 });

    const summary = await migrateLegacyLlmApiKeys(fixture.client, { activeKey: active });

    expect(summary.conflicted).toBe(1);
    expect(fixture.state[0]!.apiKeyEnvelope).toBeNull();
    expect(fixture.state[0]!.apiKey).toBe("sk-concurrent");
  });

  it("leaves a row untouched when encryption fails (fail closed)", async () => {
    const fixture = migrationFixture([{ id: "row-1", apiKey: "sk-keep-plaintext", apiKeyEnvelope: null }]);

    const summary = await migrateLegacyLlmApiKeys(fixture.client, { activeKey: {} as SecretKey });

    expect(summary.failed).toBe(1);
    expect(fixture.state[0]!.apiKey).toBe("sk-keep-plaintext");
    expect(fixture.state[0]!.apiKeyEnvelope).toBeNull();
    expect(fixture.updateMany).not.toHaveBeenCalled();
  });
});

describe("key rotation", () => {
  it("re-encrypts an old key version into the active version", async () => {
    const v1 = key(1, "rotation-v1-material-");
    const v2 = key(2, "rotation-v2-material-");
    const oldEnvelope = encryptApiKey("sk-rotate-me", v1);
    const fixture = rotationFixture([{ id: "row-1", apiKey: "", apiKeyEnvelope: oldEnvelope }]);

    const summary = await rotateLlmApiKeys(fixture.client, {
      activeKey: v2,
      lookup: buildSecretKeyLookup([v1, v2])
    });

    expect(summary).toEqual({ scanned: 1, rotated: 1, upToDate: 0, conflicted: 0, failed: 0 });
    const rotated = fixture.state[0]!.apiKeyEnvelope!;
    expect(parseEnvelope(rotated).kid).toBe(2);
    expect(decryptApiKey(rotated, buildSecretKeyLookup([v1, v2]))).toBe("sk-rotate-me");
  });

  it("leaves up-to-date envelopes alone", async () => {
    const active = key(2);
    const envelope = encryptApiKey("sk-current", active);
    const fixture = rotationFixture([{ id: "row-1", apiKey: "", apiKeyEnvelope: envelope }]);

    const summary = await rotateLlmApiKeys(fixture.client, {
      activeKey: active,
      lookup: buildSecretKeyLookup([active])
    });

    expect(summary.upToDate).toBe(1);
    expect(summary.rotated).toBe(0);
    expect(fixture.state[0]!.apiKeyEnvelope).toBe(envelope);
  });

  it("counts a missing historical key as a failure without touching the row", async () => {
    const v1 = key(1, "rotation-v1-material-");
    const v2 = key(2, "rotation-v2-material-");
    const oldEnvelope = encryptApiKey("sk-needs-v1", v1);
    const fixture = rotationFixture([{ id: "row-1", apiKey: "", apiKeyEnvelope: oldEnvelope }]);

    const summary = await rotateLlmApiKeys(fixture.client, {
      activeKey: v2,
      lookup: buildSecretKeyLookup([v2]) // v1 deliberately absent
    });

    expect(summary.failed).toBe(1);
    expect(fixture.state[0]!.apiKeyEnvelope).toBe(oldEnvelope);
  });
});

describe("destination binding (credential exfiltration fix)", () => {
  const destination = "https://llm.example/v1";

  describe("normalizeLlmDestination", () => {
    it("includes scheme, host, port and path, and ignores query/hash", () => {
      expect(normalizeLlmDestination("https://LLM.Example:8443/v1/?x=1#f")).toBe("https://llm.example:8443/v1");
    });

    it("treats trailing slashes as equivalent but real path changes as different", () => {
      expect(normalizeLlmDestination(`${destination}/`)).toBe(destination);
      expect(normalizeLlmDestination("https://llm.example/v2")).not.toBe(destination);
    });

    it("rejects unsupported schemes and embedded credentials", () => {
      expect(() => normalizeLlmDestination("javascript:alert(1)")).toThrow(LlmDestinationError);
      expect(() => normalizeLlmDestination("https://user:pass@llm.example/v1")).toThrow(LlmDestinationError);
      expect(() => normalizeLlmDestination("not a url")).toThrow(LlmDestinationError);
    });
  });

  describe("assertLlmDestination", () => {
    const row = { apiKey: "", apiKeyEnvelope: "envelope", apiKeyDestination: destination };

    it("accepts the exact approved destination", () => {
      expect(() => assertLlmDestination(row, destination)).not.toThrow();
      expect(() => assertLlmDestination(row, `${destination}/`)).not.toThrow();
    });

    it.each([
      ["hostname", "https://attacker.example/v1"],
      ["port", "https://llm.example:8443/v1"],
      ["path", "https://llm.example/v2"],
      ["scheme", "http://llm.example/v1"]
    ])("rejects a changed %s", (_label, changed) => {
      expect(() => assertLlmDestination(row, changed)).toThrow(LlmDestinationError);
    });

    it("fails closed for an unbound legacy row", () => {
      expect(() => assertLlmDestination({ ...row, apiKeyDestination: null }, destination)).toThrow(
        LlmDestinationError
      );
      expect(() => assertLlmDestination({ apiKey: "sk-legacy", apiKeyEnvelope: null }, destination)).toThrow(
        LlmDestinationError
      );
    });

    it("does not include the credential in its error message", () => {
      try {
        assertLlmDestination({ ...row, apiKey: "sk-DO-NOT-LEAK", apiKeyDestination: null }, destination);
        throw new Error("expected failure");
      } catch (error) {
        expect(error).toBeInstanceOf(LlmDestinationError);
        expect((error as Error).message).not.toContain("sk-DO-NOT-LEAK");
        expect((error as Error).message).not.toContain("envelope");
      }
    });
  });
});
