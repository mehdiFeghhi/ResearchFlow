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
const ATTACKER_URL = "https://attacker.example/v1";

type Row = {
  id: string;
  workspaceId: string;
  baseUrl: string;
  model: string;
  apiKey: string;
  apiKeyEnvelope: string | null;
  apiKeyDestination: string | null;
};

function activeKey(): SecretKey {
  return createSecretKey(2, ACTIVE_MATERIAL);
}

function encrypted(plaintext: string): string {
  return serializeEnvelope(encryptSecret(plaintext, activeKey()));
}

function rowFor(baseUrl: string, plaintext = PLAINTEXT, destination: string | null = baseUrl): Row {
  return {
    id: "row-1",
    workspaceId: "ws-1",
    baseUrl,
    model: "test-model",
    apiKey: "",
    apiKeyEnvelope: encrypted(plaintext),
    apiKeyDestination: destination
  };
}

function request(method: "PUT" | "POST", body: unknown): Request {
  return new Request("http://localhost/api/settings/llm", {
    method,
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

function stubFetch(): ReturnType<typeof vi.fn> {
  const fetchMock = vi.fn(async (_url: string, _init: RequestInit) =>
    new Response(JSON.stringify({ data: [{ id: "test-model" }] }), { status: 200 })
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

let storedRow: Row | null;

beforeEach(() => {
  storedRow = null;
  requireCurrentUser.mockResolvedValue({ workspaceId: "ws-1", role: "owner" });
  getEnv.mockReturnValue({
    LLM_KEY_ENCRYPTION_SECRET: ACTIVE_MATERIAL,
    LLM_KEY_ENCRYPTION_VERSION: 2,
    LLM_API_KEY: undefined,
    LLM_BASE_URL: BASE_URL,
    LLM_MODEL: "test-model"
  });
  // Stateful fake so PUT -> PUT -> POST chains exercise real persisted state.
  llmConfig.findUnique.mockImplementation(async () => (storedRow ? { ...storedRow } : null));
  llmConfig.upsert.mockImplementation(async (args: { update: Partial<Row>; create: Partial<Row> }) => {
    const data = storedRow ? args.update : args.create;
    storedRow = { id: "row-1", workspaceId: "ws-1", ...data } as Row;
    return { ...storedRow };
  });
  llmConfig.update.mockImplementation(async (args: { data: Partial<Row> }) => {
    storedRow = { ...storedRow!, ...args.data };
    return { ...storedRow };
  });
  researchPreferences.findUnique.mockResolvedValue({ outputLanguage: "zh" });
});

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

describe("PUT /api/settings/llm", () => {
  it("encrypts a newly created API key and binds it to the saved destination", async () => {
    const response = await PUT(request("PUT", { baseUrl: BASE_URL, model: "test-model", apiKey: PLAINTEXT }));
    const { text, json } = await body(response);

    expect(response.status).toBe(200);
    expect(llmConfig.upsert).toHaveBeenCalledTimes(1);
    const stored = llmConfig.upsert.mock.calls[0]![0] as { create: { apiKey: string; apiKeyEnvelope: string; apiKeyDestination: string } };
    expect(stored.create.apiKey).toBe("");
    expect(stored.create.apiKeyEnvelope).not.toContain(PLAINTEXT);
    expect(parseEnvelope(stored.create.apiKeyEnvelope).kid).toBe(2);
    expect(stored.create.apiKeyDestination).toBe(BASE_URL);
    expect(json.apiKeyMasked).toBe(MASKED);
    assertNoCredentialLeak(text, json, stored.create.apiKeyEnvelope);
  });

  it("re-encrypts and rebinds when a new key is saved for a different destination", async () => {
    storedRow = rowFor(BASE_URL, "sk-old-key-value-1234");
    const oldEnvelope = storedRow.apiKeyEnvelope;
    const newUrl = "https://provider-b.example/v2";

    await PUT(request("PUT", { baseUrl: newUrl, model: "test-model", apiKey: PLAINTEXT }));

    const stored = llmConfig.upsert.mock.calls[0]![0] as { update: { apiKey: string; apiKeyEnvelope: string; apiKeyDestination: string } };
    expect(stored.update.apiKey).toBe("");
    expect(stored.update.apiKeyEnvelope).not.toBe(oldEnvelope);
    expect(stored.update.apiKeyEnvelope).not.toContain(PLAINTEXT);
    expect(stored.update.apiKeyDestination).toBe(newUrl);
  });

  it("preserves the credential and its binding when the submitted key is blank", async () => {
    storedRow = rowFor(BASE_URL);
    const envelope = storedRow.apiKeyEnvelope!;

    const response = await PUT(request("PUT", { baseUrl: ATTACKER_URL, model: "new-model", apiKey: "" }));
    const { text, json } = await body(response);

    const updateArgs = llmConfig.update.mock.calls[0]![0] as { data: Record<string, unknown> };
    expect(updateArgs.data).toEqual({ baseUrl: ATTACKER_URL, model: "new-model" });
    expect(llmConfig.upsert).not.toHaveBeenCalled();
    expect(storedRow!.apiKeyEnvelope).toBe(envelope);
    expect(storedRow!.apiKeyDestination).toBe(BASE_URL);
    expect(json.apiKeyMasked).toBe(MASKED);
    assertNoCredentialLeak(text, json, envelope);
  });

  it("rejects a malformed destination without writing anything", async () => {
    const response = await PUT(
      request("PUT", { baseUrl: "javascript:alert(1)", model: "test-model", apiKey: PLAINTEXT })
    );
    expect(response.status).toBe(400);
    expect(llmConfig.upsert).not.toHaveBeenCalled();
    expect(llmConfig.update).not.toHaveBeenCalled();
  });

  it("fails closed when encryption is misconfigured (no plaintext persisted)", async () => {
    getEnv.mockReturnValue({ LLM_KEY_ENCRYPTION_SECRET: "short", LLM_KEY_ENCRYPTION_VERSION: 2 });

    await expect(
      PUT(request("PUT", { baseUrl: BASE_URL, model: "test-model", apiKey: PLAINTEXT }))
    ).rejects.toThrow();
    expect(llmConfig.upsert).not.toHaveBeenCalled();
    expect(llmConfig.update).not.toHaveBeenCalled();
  });

  it("leaves no partial key/binding state when the database write fails", async () => {
    llmConfig.upsert.mockRejectedValueOnce(new Error("db unavailable"));

    await expect(
      PUT(request("PUT", { baseUrl: BASE_URL, model: "test-model", apiKey: PLAINTEXT }))
    ).rejects.toThrow();
    expect(storedRow).toBeNull();
    expect(llmConfig.update).not.toHaveBeenCalled();
  });
});

describe("GET /api/settings/llm", () => {
  it("masks the decrypted key and never exposes plaintext or ciphertext", async () => {
    storedRow = rowFor(BASE_URL);
    const response = await GET();
    const { text, json } = await body(response);

    expect(response.status).toBe(200);
    expect(json).toMatchObject({ source: "db", baseUrl: BASE_URL, model: "test-model", outputLanguage: "zh" });
    expect(json.apiKeyMasked).toBe(MASKED);
    assertNoCredentialLeak(text, json, storedRow.apiKeyEnvelope!);
  });

  it("fails closed when a stored envelope cannot be decrypted", async () => {
    const parsed = parseEnvelope(encrypted(PLAINTEXT));
    const first = parsed.ct.charAt(0);
    storedRow = {
      ...rowFor(BASE_URL),
      apiKeyEnvelope: serializeEnvelope({ ...parsed, ct: (first === "A" ? "B" : "A") + parsed.ct.slice(1) })
    };
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

describe("POST /api/settings/llm (test connection) — destination binding", () => {
  it("uses the decrypted key for the outbound request when the destination matches", async () => {
    storedRow = rowFor(BASE_URL);
    const fetchMock = stubFetch();

    const response = await POST(request("POST", {}));
    const { text, json } = await body(response);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const init = fetchMock.mock.calls[0]![1] as unknown as { headers: Record<string, string> };
    expect(init.headers.Authorization).toBe(`Bearer ${PLAINTEXT}`);
    expect(json).toMatchObject({ ok: true, modelFound: true });
    expect(text).not.toContain(PLAINTEXT);
  });

  it("blocks the full exploit chain: save key, change baseUrl without a key, then test", async () => {
    // 1. Key saved for the legitimate provider.
    await PUT(request("PUT", { baseUrl: BASE_URL, model: "test-model", apiKey: PLAINTEXT }));
    // 2. baseUrl changed to an attacker host with no new key; binding preserved.
    await PUT(request("PUT", { baseUrl: ATTACKER_URL, model: "test-model", apiKey: "" }));
    expect(storedRow!.baseUrl).toBe(ATTACKER_URL);
    expect(storedRow!.apiKeyDestination).toBe(BASE_URL);
    // 3. Connectivity test against the attacker host without a key.
    const fetchMock = stubFetch();

    const response = await POST(request("POST", {}));

    expect(response.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toMatchObject({ error: expect.stringContaining("bound to another destination") });
    // Nothing was placed on the wire, so no Authorization header could leak.
    expect(JSON.stringify(fetchMock.mock.calls)).not.toContain("Bearer");
  });

  it("rejects an explicitly requested different destination before any request", async () => {
    storedRow = rowFor(BASE_URL);
    const fetchMock = stubFetch();

    const response = await POST(request("POST", { baseUrl: ATTACKER_URL }));

    expect(response.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("allows testing provider B after explicitly saving a new key for provider B", async () => {
    await PUT(request("PUT", { baseUrl: BASE_URL, model: "test-model", apiKey: PLAINTEXT }));
    const keyB = "sk-provider-b-key-1234";
    await PUT(request("PUT", { baseUrl: ATTACKER_URL, model: "test-model", apiKey: keyB }));
    const fetchMock = stubFetch();

    const response = await POST(request("POST", {}));

    expect(response.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const init = fetchMock.mock.calls[0]![1] as unknown as { headers: Record<string, string> };
    expect(init.headers.Authorization).toBe(`Bearer ${keyB}`);
  });

  it("does not invalidate the binding when only the model changes", async () => {
    storedRow = rowFor(BASE_URL);
    const fetchMock = stubFetch();

    const response = await POST(request("POST", { model: "another-model" }));

    expect(response.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await expect(response.json()).resolves.toMatchObject({ modelFound: false });
  });

  it.each([
    ["path", "https://llm.example/v2"],
    ["port", "https://llm.example:8443/v1"],
    ["hostname", "https://evil.example/v1"],
    ["scheme", "http://llm.example/v1"]
  ])("rejects a changed %s in the destination", async (_label, changedUrl) => {
    storedRow = rowFor(BASE_URL);
    const fetchMock = stubFetch();

    const response = await POST(request("POST", { baseUrl: changedUrl }));

    expect(response.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("accepts a trailing-slash-equivalent destination", async () => {
    storedRow = rowFor(BASE_URL);
    const fetchMock = stubFetch();

    const response = await POST(request("POST", { baseUrl: `${BASE_URL}/` }));

    expect(response.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("fails closed for an unbound legacy plaintext credential", async () => {
    storedRow = {
      id: "row-1",
      workspaceId: "ws-1",
      baseUrl: BASE_URL,
      model: "test-model",
      apiKey: PLAINTEXT,
      apiKeyEnvelope: null,
      apiKeyDestination: null
    };
    const fetchMock = stubFetch();

    const response = await POST(request("POST", {}));

    expect(response.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("fails closed for an unbound encrypted credential", async () => {
    storedRow = rowFor(BASE_URL, PLAINTEXT, null);
    const fetchMock = stubFetch();

    const response = await POST(request("POST", {}));

    expect(response.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("only uses the env fallback key for its configured destination", async () => {
    getEnv.mockReturnValue({
      LLM_KEY_ENCRYPTION_SECRET: ACTIVE_MATERIAL,
      LLM_KEY_ENCRYPTION_VERSION: 2,
      LLM_API_KEY: PLAINTEXT,
      LLM_BASE_URL: BASE_URL,
      LLM_MODEL: "test-model"
    });
    const fetchMock = stubFetch();

    const allowed = await POST(request("POST", {}));
    expect(allowed.status).toBe(200);
    const blocked = await POST(request("POST", { baseUrl: ATTACKER_URL }));
    expect(blocked.status).toBe(400);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const init = fetchMock.mock.calls[0]![1] as unknown as { headers: Record<string, string> };
    expect(init.headers.Authorization).toBe(`Bearer ${PLAINTEXT}`);
  });

  it("never includes the stored credential in a rejected response", async () => {
    storedRow = rowFor(BASE_URL);
    stubFetch();

    const response = await POST(request("POST", { baseUrl: ATTACKER_URL }));
    const { text, json } = await body(response);

    assertNoCredentialLeak(text, json, storedRow.apiKeyEnvelope!);
  });
});
