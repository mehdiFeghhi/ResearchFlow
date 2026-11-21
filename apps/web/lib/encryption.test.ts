import { describe, expect, it } from "vitest";
import {
  createSecretKey,
  decryptSecret,
  encryptSecret,
  parseEnvelope,
  SecretEncryptionError,
  serializeEnvelope,
  type EncryptedEnvelope,
  type SecretKey
} from "./encryption";

/** Deterministic but non-production key material — tests never weaken the helper's randomness. */
function testKey(version = 1, seed = "test-key-material-"): SecretKey {
  return createSecretKey(version, seed.repeat(4));
}

function flipFirstChar(value: string): string {
  const first = value.charAt(0);
  return (first === "A" ? "B" : "A") + value.slice(1);
}

function withField(env: EncryptedEnvelope, patch: Partial<EncryptedEnvelope>): EncryptedEnvelope {
  return { ...env, ...patch };
}

describe("envelope encryption", () => {
  describe("round-trip", () => {
    it("encrypts and decrypts a secret using the same key", () => {
      const key = testKey();
      const plaintext = "sk-this-is-a-very-secret-llm-api-key";
      const envelope = encryptSecret(plaintext, key);

      expect(envelope.v).toBe(1);
      expect(envelope.alg).toBe("A256GCM");
      expect(envelope.kdf).toBe("HKDF-SHA256");
      expect(envelope.kid).toBe(1);
      // 12-byte nonce, 16-byte tag, both canonical base64url.
      expect(Buffer.from(envelope.iv, "base64url")).toHaveLength(12);
      expect(Buffer.from(envelope.tag, "base64url")).toHaveLength(16);
      expect(Buffer.from(envelope.ct, "base64url").length).toBe(Buffer.byteLength(plaintext, "utf8"));

      expect(decryptSecret(envelope, key)).toBe(plaintext);
    });

    it("round-trips unicode and long secrets", () => {
      const key = testKey(3);
      const plaintext = "密钥-🔐-" + "x".repeat(10_000);
      expect(decryptSecret(encryptSecret(plaintext, key), key)).toBe(plaintext);
    });

    it("survives JSON serialization and parsing", () => {
      const key = testKey();
      const envelope = encryptSecret("sk-serialized", key);
      const wire = serializeEnvelope(envelope);
      expect(typeof wire).toBe("string");
      expect(parseEnvelope(wire)).toEqual(envelope);
      expect(decryptSecret(wire, key)).toBe("sk-serialized");
    });
  });

  describe("nonce uniqueness", () => {
    it("produces different ciphertexts and IVs for the same plaintext and key", () => {
      const key = testKey();
      const plaintext = "sk-repeat-me";
      const a = encryptSecret(plaintext, key);
      const b = encryptSecret(plaintext, key);

      expect(a.iv).not.toBe(b.iv);
      expect(a.ct).not.toBe(b.ct);
      expect(a.tag).not.toBe(b.tag);
      expect(decryptSecret(a, key)).toBe(plaintext);
      expect(decryptSecret(b, key)).toBe(plaintext);
    });
  });

  describe("authentication failures", () => {
    it("rejects tampered ciphertext", () => {
      const key = testKey();
      const envelope = encryptSecret("sk-tamper-ct", key);
      const tampered = withField(envelope, { ct: flipFirstChar(envelope.ct) });

      expect(() => decryptSecret(tampered, key)).toThrow(SecretEncryptionError);
    });

    it("rejects a tampered authentication tag", () => {
      const key = testKey();
      const envelope = encryptSecret("sk-tamper-tag", key);
      const tampered = withField(envelope, { tag: flipFirstChar(envelope.tag) });

      expect(() => decryptSecret(tampered, key)).toThrow(SecretEncryptionError);
    });

    it("rejects a wrong encryption key with the same version", () => {
      const envelope = encryptSecret("sk-wrong-key", testKey(1, "original-key-material-"));
      const wrong = testKey(1, "different-key-material-");

      expect(() => decryptSecret(envelope, wrong)).toThrow(SecretEncryptionError);
    });

    it("rejects a key whose version does not match the envelope", () => {
      const envelope = encryptSecret("sk-wrong-version", testKey(1));
      const wrongVersion = testKey(2);

      expect(() => decryptSecret(envelope, wrongVersion)).toThrow(SecretEncryptionError);
    });

    it("rejects a lookup that returns a key with the wrong version", () => {
      const envelope = encryptSecret("sk-lookup-version", testKey(1));
      const lookup = () => testKey(2);

      expect(() => decryptSecret(envelope, lookup)).toThrow(SecretEncryptionError);
    });

    it("rejects a lookup with no key for the envelope's version", () => {
      const envelope = encryptSecret("sk-no-key", testKey(1));
      const lookup = (version: number) => (version === 1 ? undefined : testKey(version));

      expect(() => decryptSecret(envelope, lookup)).toThrow(SecretEncryptionError);
    });

    it("rejects metadata tampering that is structurally valid (AAD mismatch)", () => {
      const key = testKey();
      const envelope = encryptSecret("sk-aad", key);

      // kid and iv are authenticated as AAD: changing them must break GCM auth.
      expect(() => decryptSecret(withField(envelope, { kid: 2 }), key)).toThrow(SecretEncryptionError);
      expect(() => decryptSecret(withField(envelope, { iv: flipFirstChar(envelope.iv) }), key)).toThrow(
        SecretEncryptionError
      );
    });

    it("keeps metadata tampering from succeeding even with a matching lookup key", () => {
      const v1 = testKey(1, "key-v1-material-");
      const v2 = testKey(2, "key-v2-material-");
      const envelope = encryptSecret("sk-aad-rotation", v1);
      const tamperedKid = withField(envelope, { kid: 2 });
      const lookup = (version: number) => (version === 1 ? v1 : version === 2 ? v2 : undefined);

      expect(() => decryptSecret(tamperedKid, lookup)).toThrow(SecretEncryptionError);
    });
  });

  describe("envelope validation", () => {
    it("rejects an unsupported envelope version", () => {
      const envelope = encryptSecret("sk-version", testKey());
      expect(() => parseEnvelope(withField(envelope, { v: 2 as never }))).toThrow(SecretEncryptionError);
    });

    it("rejects an unsupported algorithm or KDF identifier", () => {
      const envelope = encryptSecret("sk-alg", testKey());
      expect(() => parseEnvelope(withField(envelope, { alg: "AES-128-CBC" as never }))).toThrow(
        SecretEncryptionError
      );
      expect(() => parseEnvelope(withField(envelope, { kdf: "PBKDF2" as never }))).toThrow(SecretEncryptionError);
    });

    it.each([
      ["not json at all", "invalid JSON"],
      ["{}", "missing fields"],
      ['{"v":1,"alg":"A256GCM","kdf":"HKDF-SHA256","kid":1,"iv":"!!","tag":"AA","ct":"AA","extra":1}', "extra field / bad base64url"],
      ['{"v":1,"alg":"A256GCM","kdf":"HKDF-SHA256","kid":0,"iv":"AAAAAAAAAAAAAAAA","tag":"AAAAAAAAAAAAAAAAAAAAAA","ct":"QQ"}', "invalid key version"],
      ['{"v":1,"alg":"A256GCM","kdf":"HKDF-SHA256","kid":1,"iv":"short","tag":"AAAAAAAAAAAAAAAAAAAAAA","ct":"QQ"}', "short nonce"]
    ])("rejects malformed envelope: %s (%s)", (input) => {
      expect(() => parseEnvelope(input)).toThrow(SecretEncryptionError);
    });

    it("rejects non-canonical base64url in envelope fields", () => {
      const envelope = encryptSecret("sk-canonical", testKey());
      // A 12-byte nonce encodes to 16 base64url chars; pad with '=' (not allowed).
      expect(() => parseEnvelope(withField(envelope, { iv: envelope.iv + "=" }))).toThrow(SecretEncryptionError);
    });
  });

  describe("invalid inputs", () => {
    it("rejects empty and non-string plaintext", () => {
      const key = testKey();
      expect(() => encryptSecret("", key)).toThrow(SecretEncryptionError);
      expect(() => encryptSecret(null as never, key)).toThrow(SecretEncryptionError);
      expect(() => encryptSecret(42 as never, key)).toThrow(SecretEncryptionError);
    });

    it("rejects short or invalid key material", () => {
      expect(() => createSecretKey(1, "too-short")).toThrow(SecretEncryptionError);
      expect(() => createSecretKey(0, "x".repeat(48))).toThrow(SecretEncryptionError);
      expect(() => createSecretKey(1.5, "x".repeat(48))).toThrow(SecretEncryptionError);
      expect(() => encryptSecret("sk-x", undefined as never)).toThrow(SecretEncryptionError);
      expect(() => decryptSecret(encryptSecret("sk-x", testKey()), undefined as never)).toThrow(
        SecretEncryptionError
      );
    });

    it("does not leak plaintext or key material in error messages", () => {
      const key = testKey(1, "super-secret-key-material-");
      const plaintext = "sk-DO-NOT-LEAK-THIS";
      const envelope = encryptSecret(plaintext, key);
      const wrong = testKey(1, "another-secret-key-material-");

      for (const action of [
        () => decryptSecret(withField(envelope, { ct: flipFirstChar(envelope.ct) }), key),
        () => decryptSecret(envelope, wrong),
        () => encryptSecret(plaintext, createSecretKey(1, "short"))
      ]) {
        try {
          action();
          throw new Error("expected failure");
        } catch (error) {
          expect(error).toBeInstanceOf(SecretEncryptionError);
          const message = (error as Error).message;
          expect(message).not.toContain(plaintext);
          expect(message).not.toContain("super-secret-key-material-");
          expect(message).not.toContain(envelope.ct);
        }
      }
    });
  });

  describe("key rotation support", () => {
    it("decrypts old ciphertext through a version-aware lookup", () => {
      const v1 = testKey(1, "rotation-key-v1-material-");
      const v2 = testKey(2, "rotation-key-v2-material-");
      const oldEnvelope = encryptSecret("sk-from-v1", v1);
      const newEnvelope = encryptSecret("sk-from-v2", v2);
      const keyring = [v1, v2];
      const lookup = (version: number) => keyring.find((candidate) => candidate.version === version);

      expect(oldEnvelope.kid).toBe(1);
      expect(newEnvelope.kid).toBe(2);
      expect(decryptSecret(oldEnvelope, lookup)).toBe("sk-from-v1");
      expect(decryptSecret(newEnvelope, lookup)).toBe("sk-from-v2");
    });
  });
});
