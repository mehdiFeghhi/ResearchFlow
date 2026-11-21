-- P1-T02.1: bind a stored LLM credential to the provider destination that was
-- approved when the key was saved (credential-exfiltration fix).
--
-- Additive only: no existing column is changed, dropped or rewritten. Rows that
-- predate this migration keep NULL and are treated as unbound; their key is not
-- authorized for any outbound destination until it is explicitly re-entered
-- through Settings -> LLM (which writes this column atomically with the key).
ALTER TABLE "LlmConfig" ADD COLUMN "apiKeyDestination" TEXT;
