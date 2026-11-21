import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createSecretKey,
  encryptSecret,
  parseEnvelope,
  serializeEnvelope,
  type SecretKey
} from "@/lib/encryption";

const { llmConfig, researchPreferences, requireCurrentUser, getEnv } = vi.hoisted(() => ({
  llmConfig: { findUnique: vi.fn(), upsert: vi.fn(), update: vi.fn() },
  researchPreferences: { findUnique: vi.fn(), upsert: vi.fn() },
  requireCurrentUser: vi.fn(),
  getEnv: vi.fn()
}));

vi.mock("@paper-viewer/db", () => ({ prisma: { llmConfig, researchPreferences } }));
vi.mock("@/lib/auth", () => ({ requireCurrentUser }));
vi.mock("@/lib/env", () => ({ getEnv }));

const { GET, PUT, POST } = await import("./route");

const ACTIVE_MATERIAL = "active-key-material-at-least-32-bytes";
const PLAINTEXT = "sk-abcdefghijklmnop";
const MASKED = "sk-***mnop";
const BASE_URL = "https://llm.example/v1";

function activeKey(): SecretKey {
  return createSecretKey(2, ACTIVE_MATERIAL);
}

function encrypted(plaintext: string): string {
  return serializeEnvelope(encryptSecret(plaintext, activeKey()));
}

function request(body: unknown): Request {
  return new Request("http://localhost/api/settings/llm", {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
}

async function body(response: Response): Promise<{ text: string; json: Record<string, unknown> }> {
  const text = await response.text();
  return { text, json: JSON.parse(text) as Record<string, unknown> };
}

function assertNoCredentialLeak(text: string, json: Record<string, unknown>, envelope?: string): void {
  expect(text).not.toContain(PLAINTEXT);
  expect(json).not.toHaveProperty("apiKey");
  expect(json).not.toHaveProperty("apiKeyEnvelope");
  if (envelope) expect(text).not.toContain(envelope);
}

beforeEach(() => {
  requireCurrentUser.mockResolvedValue({ workspaceId: "ws-1", role: "owner" });
  getEnv.mockReturnValue({
    LLM_KEY_ENCRYPTION_SECRET: ACTIVE_MATERIAL,
    LLM_KEY_ENCRYPTION_VERSION: 2,
    LLM_API_KEY: undefined,
    LLM_BASE_URL: BASE_URL,
    LLM_MODEL: "test-model"
  });
  llmConfig.findUnique.mockResolvedValue(null);
  llmConfig.upsert.mockImplementation(async ({ create }) => ({ id: "row-1", ...create }));
  llmConfig.update.mockImplementation(async ({ data }) => ({ id: "row-1", ...data }));
  researchPreferences.findUnique.mockResolvedValue({ outputLanguage: "zh" });
});

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

describe("PUT /api/settings/llm", () => {
  it("encrypts a newly created API key before persistence", async () => {
    const response = await PUT(request({ baseUrl: BASE_URL, model: "test-model", apiKey: PLAINTEXT }));
    const { text, json } = await body(response);

    expect(response.status).toBe(200);
    expect(llmConfig.upsert).toHaveBeenCalledTimes(1);
    const stored = llmConfig.upsert.mock.calls[0]![0] as { create: { apiKey: string; apiKeyEnvelope: string } };
    expect(stored.create.apiKey).toBe("");
    expect(stored.create.apiKeyEnvelope).not.toContain(PLAINTEXT);
    expect(parseEnvelope(stored.create.apiKeyEnvelope).kid).toBe(2);
    expect(encryptSecret(PLAINTEXT, activeKey())).toBeTruthy(); // helper sanity
    expect(json.apiKeyMasked).toBe(MASKED);
    assertNoCredentialLeak(text, json, stored.create.apiKeyEnvelope);
  });

  it("re-encrypts when updating an existing API key", async () => {
    const oldEnvelope = encrypted("sk-old-key-value-1234");
    llmConfig.upsert.mockImplementation(async ({ update }) => ({ id: "row-1", ...update }));

    await PUT(request({ baseUrl: BASE_URL, model: "test-model", apiKey: PLAINTEXT }));

    const stored = llmConfig.upsert.mock.calls[0]![0] as { update: { apiKey: string; apiKeyEnvelope: string } };
    expect(stored.update.apiKey).toBe("");
    expect(stored.update.apiKeyEnvelope).not.toBe(oldEnvelope);
    expect(stored.update.apiKeyEnvelope).not.toContain(PLAINTEXT);
  });

  it("preserves an existing encrypted key when the submitted key is blank", async () => {
    const envelope = encrypted(PLAINTEXT);
    llmConfig.findUnique.mockResolvedValue({
      id: "row-1",
      workspaceId: "ws-1",
      baseUrl: BASE_URL,
      model: "old-model",
      apiKey: "",
      apiKeyEnvelope: envelope
    });

    const response = await PUT(request({ baseUrl: BASE_URL, model: "new-model", apiKey: "" }));
    const { text, json } = await body(response);

    const updateArgs = llmConfig.update.mock.calls[0]![0] as { data: Record<string, unknown> };
    expect(updateArgs.data).toEqual({ baseUrl: BASE_URL, model: "new-model" });
    expect(llmConfig.upsert).not.toHaveBeenCalled();
    expect(json.apiKeyMasked).toBe(MASKED);
    assertNoCredentialLeak(text, json, envelope);
  });

  it("fails closed when encryption is misconfigured (no plaintext persisted)", async () => {
    getEnv.mockReturnValue({
      LLM_KEY_ENCRYPTION_SECRET: "short",
      LLM_KEY_ENCRYPTION_VERSION: 2
    });

    await expect(PUT(request({ baseUrl: BASE_URL, model: "test-model", apiKey: PLAINTEXT }))).rejects.toThrow();
    expect(llmConfig.upsert).not.toHaveBeenCalled();
    expect(llmConfig.update).not.toHaveBeenCalled();
  });
});

describe("GET /api/settings/llm", () => {
  it("masks the decrypted key and never exposes plaintext or ciphertext", async () => {
    const envelope = encrypted(PLAINTEXT);
    llmConfig.findUnique.mockResolvedValue({
      id: "row-1",
      workspaceId: "ws-1",
      baseUrl: BASE_URL,
      model: "test-model",
      apiKey: "",
      apiKeyEnvelope: envelope
    });

    const response = await GET();
    const { text, json } = await body(response);

    expect(response.status).toBe(200);
    expect(json).toMatchObject({ source: "db", baseUrl: BASE_URL, model: "test-model", outputLanguage: "zh" });
    expect(json.apiKeyMasked).toBe(MASKED);
    assertNoCredentialLeak(text, json, envelope);
  });

  it("fails closed when a stored envelope cannot be decrypted", async () => {
    const parsed = parseEnvelope(encrypted(PLAINTEXT));
    const first = parsed.ct.charAt(0);
    llmConfig.findUnique.mockResolvedValue({
      id: "row-1",
      workspaceId: "ws-1",
      baseUrl: BASE_URL,
      model: "test-model",
      apiKey: "",
      apiKeyEnvelope: serializeEnvelope({ ...parsed, ct: (first === "A" ? "B" : "A") + parsed.ct.slice(1) })
    });

    await expect(GET()).rejects.toThrow();
  });

  it("still masks the env fallback key", async () => {
    getEnv.mockReturnValue({
      LLM_KEY_ENCRYPTION_SECRET: ACTIVE_MATERIAL,
      LLM_KEY_ENCRYPTION_VERSION: 2,
      LLM_API_KEY: PLAINTEXT,
      LLM_BASE_URL: BASE_URL,
      LLM_MODEL: "test-model"
    });

    const response = await GET();
    const { text, json } = await body(response);

    expect(json).toMatchObject({ source: "env", apiKeyMasked: MASKED });
    assertNoCredentialLeak(text, json);
  });
});

describe("POST /api/settings/llm (test connection)", () => {
  it("uses the decrypted key for the outbound request without leaking it", async () => {
    llmConfig.findUnique.mockResolvedValue({
      id: "row-1",
      workspaceId: "ws-1",
      baseUrl: BASE_URL,
      model: "test-model",
      apiKey: "",
      apiKeyEnvelope: encrypted(PLAINTEXT)
    });
    const fetchMock = vi.fn(async (_url: string, _init: RequestInit) =>
      new Response(JSON.stringify({ data: [{ id: "test-model" }] }), { status: 200 })
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await POST(
      new Request("http://localhost/api/settings/llm", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({})
      })
    );
    const { text, json } = await body(response);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const init = fetchMock.mock.calls[0]![1] as unknown as { headers: Record<string, string> };
    expect(init.headers.Authorization).toBe(`Bearer ${PLAINTEXT}`);
    expect(json).toMatchObject({ ok: true, modelFound: true });
    expect(text).not.toContain(PLAINTEXT);
  });

  it("does not attach the stored key when the base URL changes", async () => {
    llmConfig.findUnique.mockResolvedValue({
      id: "row-1",
      workspaceId: "ws-1",
      baseUrl: BASE_URL,
      model: "test-model",
      apiKey: "",
      apiKeyEnvelope: encrypted(PLAINTEXT)
    });
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const response = await POST(
      new Request("http://localhost/api/settings/llm", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ baseUrl: "https://attacker.example/v1" })
      })
    );

    expect(fetchMock).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toMatchObject({ ok: false });
  });
});
