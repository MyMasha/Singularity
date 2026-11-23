#!/usr/bin/env node
/**
 * Automated test suite for lean-max-orchestrator PreToolUse hook.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { evaluatePreToolUse, loadConfig } from "./enforce-subagent-contract.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const HOOK_SCRIPT = path.join(__dirname, "enforce-subagent-contract.mjs");
const config = loadConfig();

// 1. Enriches regular subagent calls lacking marker
{
  const out = evaluatePreToolUse(
    {
      toolCall: {
        name: "invoke_subagent",
        args: {
          TypeName: "self",
          Role: "Backend Fixer",
          Prompt: "Corrige le bug de parsing dans src/parser.ts",
        },
      },
    },
    config
  );
  assert.equal(out.decision, "allow");
  assert.ok(out.overwrite && typeof out.overwrite.Prompt === "string");
  assert.ok(out.overwrite.Prompt.includes("[MAX-DEPTH/LEAN-REPORT]"));
  assert.ok(out.overwrite.Prompt.includes("n'économise JAMAIS tes propres tokens"));
}

// 2. Idempotent when marker is already present
{
  const out = evaluatePreToolUse(
    {
      toolCall: {
        name: "invoke_subagent",
        args: {
          TypeName: "deep-worker",
          Role: "Worker",
          Prompt: "[MAX-DEPTH/LEAN-REPORT] Corrige src/app.ts",
        },
      },
    },
    config
  );
  assert.deepEqual(out, { decision: "allow" });
}

// 3. Skips excluded specialized subagents (browser, image-generator)
for (const excludedType of ["browser", "image-generator"]) {
  const out = evaluatePreToolUse(
    {
      toolCall: {
        name: "invoke_subagent",
        args: {
          TypeName: excludedType,
          Role: "Specialized",
          Prompt: "Open localhost:3000",
        },
      },
    },
    config
  );
  assert.deepEqual(out, { decision: "allow" });
}

// 4. Ignores unrelated tools
{
  const out = evaluatePreToolUse(
    {
      toolCall: {
        name: "run_command",
        args: { CommandLine: "npm test" },
      },
    },
    config
  );
  assert.deepEqual(out, { decision: "allow" });
}

// 5. End-to-end subprocess stdin -> stdout test
{
  const payload = JSON.stringify({
    conversationId: "conv-123",
    hookEventName: "PreToolUse",
    toolCall: {
      id: "toolu_01",
      name: "invoke_subagent",
      args: {
        TypeName: "research",
        Role: "Security Auditor",
        Prompt: "Audite src/auth/ pour les failles JWT.",
      },
    },
  });

  const proc = spawnSync(process.execPath, [HOOK_SCRIPT], {
    input: payload,
    encoding: "utf8",
  });
  assert.equal(proc.status, 0, `Hook failed: ${proc.stderr}`);
  const parsed = JSON.parse(proc.stdout);
  assert.equal(parsed.decision, "allow");
  assert.ok(parsed.overwrite.Prompt.includes("[MAX-DEPTH/LEAN-REPORT]"));
  console.log("E2E PreToolUse hook OK");
}

console.log("ALL ORCHESTRATOR TESTS PASSED!");
