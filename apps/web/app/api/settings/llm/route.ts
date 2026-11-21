import { prisma } from "@paper-viewer/db";
import { z } from "zod";
import { canManageWorkspaceSettings } from "@paper-viewer/core/permissions";
import {
  isOutputLanguage,
  maskApiKey,
  toOutputLanguage,
  type OutputLanguage
} from "@paper-viewer/core/llm-config";
import { requireCurrentUser, type CurrentUser } from "@/lib/auth";
import { getEnv } from "@/lib/env";
import {
  assertLlmDestination,
  encryptApiKey,
  LlmDestinationError,
  normalizeLlmDestination,
  readStoredApiKey
} from "@/lib/llm-key-store";

type ConfigSource = "db" | "env" | "none";

type EffectiveConfig = {
  source: ConfigSource;
  baseUrl: string;
  model: string;
  apiKey: string;
};

type ConfigView = {
  source: ConfigSource;
  baseUrl: string;
  model: string;
  apiKeyMasked: string;
};

/**
 * The output language is surfaced on this page but stored on
 * ResearchPreferences, not LlmConfig: a workspace running on the env-level
 * model has no LlmConfig row at all, and it must still be able to choose a
 * language. It therefore has its own PATCH rather than riding along with the
 * key/model form, whose first save requires an API key.
 */
async function loadOutputLanguage(workspaceId: string): Promise<OutputLanguage> {
  const prefs = await prisma.researchPreferences.findUnique({
    where: { workspaceId },
    select: { outputLanguage: true }
  });
  return toOutputLanguage(prefs?.outputLanguage);
}

const TEST_TIMEOUT_MS = 15_000;
const MAX_LISTED_MODELS = 10;

const updateSchema = z.object({
  baseUrl: z.string().url(),
  model: z.string().min(1).max(100),
  apiKey: z.string().max(200).optional()
});

const testSchema = z.object({
  baseUrl: z.string().url().optional(),
  model: z.string().min(1).max(100).optional(),
  apiKey: z.string().max(200).optional()
});

async function resolveCurrentUser(): Promise<CurrentUser | null> {
  try {
    return await requireCurrentUser();
  } catch {
    return null;
  }
}

/** The DB row wins, then env; if neither exists the source is none (the env default baseUrl/model is still returned so the frontend can prefill). */
async function loadEffectiveConfig(workspaceId: string): Promise<EffectiveConfig> {
  const row = await prisma.llmConfig.findUnique({ where: { workspaceId } });
  if (row) {
    return {
      source: "db",
      baseUrl: row.baseUrl,
      model: row.model,
      // Server-only decryption; the plaintext is used for masking and for the
      // test request but is never placed in a response object.
      apiKey: readStoredApiKey({ apiKey: row.apiKey, apiKeyEnvelope: row.apiKeyEnvelope })
    };
  }

  const env = getEnv();
  if (env.LLM_API_KEY) {
    return { source: "env", baseUrl: env.LLM_BASE_URL, model: env.LLM_MODEL, apiKey: env.LLM_API_KEY };
  }

  return { source: "none", baseUrl: env.LLM_BASE_URL, model: env.LLM_MODEL, apiKey: "" };
}

function toConfigView(config: EffectiveConfig): ConfigView {
  return {
    source: config.source,
    baseUrl: config.baseUrl,
    model: config.model,
    apiKeyMasked: maskApiKey(config.apiKey)
  };
}

function trimmedOrEmpty(value: string | undefined): string {
  return value?.trim() ?? "";
}

function normalizeBaseUrl(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, "");
}

function extractModelIds(payload: unknown): string[] {
  if (typeof payload !== "object" || payload === null) return [];
  const data = (payload as { data?: unknown }).data;
  if (!Array.isArray(data)) return [];
  return data
    .map((entry) => (typeof entry === "object" && entry !== null ? (entry as { id?: unknown }).id : undefined))
    .filter((id): id is string => typeof id === "string");
}

function extractErrorMessage(payload: unknown, fallback: string): string {
  if (typeof payload !== "object" || payload === null) return fallback;
  const error = (payload as { error?: unknown }).error;
  if (typeof error === "string" && error) return error;
  if (typeof error === "object" && error !== null) {
    const message = (error as { message?: unknown }).message;
    if (typeof message === "string" && message) return message;
  }
  const message = (payload as { message?: unknown }).message;
  if (typeof message === "string" && message) return message;
  return fallback;
}

export async function GET() {
  const user = await resolveCurrentUser();
  if (!user) {
    return Response.json({ error: "Authentication required" }, { status: 401 });
  }
  if (!canManageWorkspaceSettings(user.role)) {
    return Response.json({ error: "Forbidden" }, { status: 403 });
  }

  const [config, outputLanguage] = await Promise.all([
    loadEffectiveConfig(user.workspaceId),
    loadOutputLanguage(user.workspaceId)
  ]);
  return Response.json({ ...toConfigView(config), outputLanguage });
}

export async function PATCH(request: Request) {
  const user = await resolveCurrentUser();
  if (!user) {
    return Response.json({ error: "Authentication required" }, { status: 401 });
  }
  if (!canManageWorkspaceSettings(user.role)) {
    return Response.json({ error: "Forbidden" }, { status: 403 });
  }

  const body = (await request.json()) as { outputLanguage?: unknown };
  if (!isOutputLanguage(body.outputLanguage)) {
    return Response.json({ error: "Unsupported output language" }, { status: 400 });
  }
  const outputLanguage = body.outputLanguage;

  // Only this column is written, so saving a language can never clear the
  // research topics the same row carries.
  await prisma.researchPreferences.upsert({
    where: { workspaceId: user.workspaceId },
    update: { outputLanguage },
    create: { workspaceId: user.workspaceId, outputLanguage }
  });

  return Response.json({ outputLanguage });
}

export async function PUT(request: Request) {
  const user = await resolveCurrentUser();
  if (!user) {
    return Response.json({ error: "Authentication required" }, { status: 401 });
  }
  if (!canManageWorkspaceSettings(user.role)) {
    return Response.json({ error: "Forbidden" }, { status: 403 });
  }

  const input = updateSchema.parse(await request.json());
  const baseUrl = input.baseUrl.trim();
  const model = input.model.trim();
  const apiKey = trimmedOrEmpty(input.apiKey);

  if (apiKey) {
    // The destination is approved together with the key: normalize it before
    // any write so a malformed URL can never be persisted as a binding.
    let apiKeyDestination: string;
    try {
      apiKeyDestination = normalizeLlmDestination(baseUrl);
    } catch {
      return Response.json({ error: "Invalid LLM base URL" }, { status: 400 });
    }
    // Encrypt before persistence: the plaintext key never reaches Postgres.
    // Envelope, binding and legacy-column clearing are written in one UPSERT,
    // so a failed update cannot leave a key attached to the wrong destination.
    const apiKeyEnvelope = encryptApiKey(apiKey);
    const row = await prisma.llmConfig.upsert({
      where: { workspaceId: user.workspaceId },
      update: { baseUrl, model, apiKeyEnvelope, apiKeyDestination, apiKey: "" },
      create: { workspaceId: user.workspaceId, baseUrl, model, apiKeyEnvelope, apiKeyDestination, apiKey: "" }
    });
    return Response.json(toConfigView({ source: "db", baseUrl: row.baseUrl, model: row.model, apiKey }));
  }

  const existing = await prisma.llmConfig.findUnique({ where: { workspaceId: user.workspaceId } });
  if (!existing) {
    return Response.json({ error: "首次保存必须提供 API Key" }, { status: 400 });
  }

  // Blank key means "keep the existing one": touch only baseUrl/model, never
  // the credential or its destination binding. The key is preserved but is NOT
  // authorized for a changed baseUrl (see POST / resolveLlmConfig).
  const row = await prisma.llmConfig.update({
    where: { workspaceId: user.workspaceId },
    data: { baseUrl, model }
  });
  return Response.json(
    toConfigView({
      source: "db",
      baseUrl: row.baseUrl,
      model: row.model,
      apiKey: readStoredApiKey({ apiKey: existing.apiKey, apiKeyEnvelope: existing.apiKeyEnvelope })
    })
  );
}

export async function POST(request: Request) {
  const user = await resolveCurrentUser();
  if (!user) {
    return Response.json({ error: "Authentication required" }, { status: 401 });
  }
  if (!canManageWorkspaceSettings(user.role)) {
    return Response.json({ error: "Forbidden" }, { status: 403 });
  }

  const input = testSchema.parse(await request.json());
  const row = await prisma.llmConfig.findUnique({ where: { workspaceId: user.workspaceId } });
  const env = getEnv();
  const baseUrl = trimmedOrEmpty(input.baseUrl) || row?.baseUrl || env.LLM_BASE_URL;
  const model = trimmedOrEmpty(input.model) || row?.model || env.LLM_MODEL;

  // Test requests follow the same rule as saving: https only, to close off an SSRF
  // surface on the admin side (same as the notifications route)
  if (!z.string().url().safeParse(baseUrl).success || !baseUrl.startsWith("https://")) {
    return Response.json({ error: "Base URL 必须是 https 地址" }, { status: 400 });
  }

  // A submitted key is explicitly provided for this destination by the caller;
  // no stored credential is involved.
  let apiKey = trimmedOrEmpty(input.apiKey);
  const unauthorized = () =>
    Response.json(
      { error: "Stored API key is bound to another destination. Re-enter the key to test a new base URL." },
      { status: 400 }
    );

  if (!apiKey && row && (row.apiKeyEnvelope || row.apiKey)) {
    // Check the persisted binding BEFORE decrypting or sending anything. The
    // row's mutable baseUrl is deliberately not used as evidence of approval:
    // it may have been changed to an attacker-controlled destination.
    try {
      assertLlmDestination(row, baseUrl);
    } catch (error) {
      if (error instanceof LlmDestinationError) return unauthorized();
      throw error;
    }
    apiKey = readStoredApiKey(row);
  } else if (!apiKey && !row && env.LLM_API_KEY) {
    // Deployment-owned fallback key: its approved destination is the env config.
    let matches = false;
    try {
      matches = normalizeLlmDestination(baseUrl) === normalizeLlmDestination(env.LLM_BASE_URL);
    } catch {
      matches = false;
    }
    if (!matches) return unauthorized();
    apiKey = env.LLM_API_KEY;
  }

  if (!apiKey) {
    return Response.json({
      ok: false,
      status: 0,
      message: "更换 Base URL 测试时需提供对应的 API Key"
    });
  }

  let response: Response;
  try {
    response = await fetch(`${normalizeBaseUrl(baseUrl)}/models`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      signal: AbortSignal.timeout(TEST_TIMEOUT_MS)
    });
  } catch {
    return Response.json({ ok: false, status: 0, message: "连接失败或超时" });
  }

  const payload = await response.json().catch(() => null);

  if (!response.ok) {
    return Response.json({
      ok: false,
      status: response.status,
      message: extractErrorMessage(payload, `HTTP ${response.status}`)
    });
  }

  const modelIds = extractModelIds(payload);
  return Response.json({
    ok: true,
    total: modelIds.length,
    models: modelIds.slice(0, MAX_LISTED_MODELS),
    modelFound: modelIds.includes(model)
  });
}
