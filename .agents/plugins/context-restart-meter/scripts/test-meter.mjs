#!/usr/bin/env node
/**
 * Automated verification suite for Context Restart Meter.
 * Tests all thresholds (0-49%, 50-79%, 80-99%, 100%), compaction weighting,
 * same-turn deduplication, and real stdin/stdout hook execution.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  computeStatus,
  evaluateHookPayload,
  loadConfig,
} from "./context-meter.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const HOOK_SCRIPT = path.join(__dirname, "context-meter.mjs");
const config = loadConfig();

function writeTempTranscript(steps) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agy-ctx-meter-"));
  const file = path.join(dir, "transcript.jsonl");
  fs.writeFileSync(file, steps.map((s) => JSON.stringify(s)).join("\n") + "\n", "utf8");
  return { dir, file };
}

function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

// 1. Threshold mapping tests
{
  const s15 = computeStatus(
    { activeTokens: 72000, maxTokens: 480000, checkpointCount: 0, measurementSource: "transcript" },
    config
  );
  assert.equal(s15.restartPct, 15);
  assert.equal(s15.tier, "ok");
  assert.match(s15.label, /OK/i);

  const s50 = computeStatus(
    { activeTokens: 240000, maxTokens: 480000, checkpointCount: 0, measurementSource: "transcript" },
    config
  );
  assert.equal(s50.restartPct, 50);
  assert.equal(s50.tier, "soon");
  assert.match(s50.label, /Dans pas longtemps/i);

  const s80 = computeStatus(
    { activeTokens: 384000, maxTokens: 480000, checkpointCount: 0, measurementSource: "transcript" },
    config
  );
  assert.equal(s80.restartPct, 80);
  assert.equal(s80.tier, "restart");
  assert.match(s80.label, /Relancer une nouvelle conversation/i);

  const s100 = computeStatus(
    { activeTokens: 490000, maxTokens: 480000, checkpointCount: 0, measurementSource: "transcript" },
    config
  );
  assert.equal(s100.restartPct, 100);
  assert.equal(s100.tier, "critical");
  assert.match(s100.label, /Il faut absolument relancer/i);
}

// 2. Compaction weighting test (prevents false "10%" reset after auto-compaction)
{
  const after1 = computeStatus(
    { activeTokens: 48000, maxTokens: 480000, checkpointCount: 1, measurementSource: "transcript" },
    config
  );
  assert.ok(after1.restartPct >= 55 && after1.restartPct < 80, `Expected 55-79%, got ${after1.restartPct}%`);
  assert.equal(after1.tier, "soon");
  assert.match(after1.details, /déjà compactée 1×/);

  const after2 = computeStatus(
    { activeTokens: 48000, maxTokens: 480000, checkpointCount: 2, measurementSource: "transcript" },
    config
  );
  assert.ok(after2.restartPct >= 80, `Expected >=80%, got ${after2.restartPct}%`);
  assert.equal(after2.tier, "restart");
}

// 3. Same-turn deduplication + jump reinjection
{
  const { dir, file } = writeTempTranscript([
    { step_index: 0, type: "USER_INPUT", content: "Bonjour" },
    {
      step_index: 1,
      type: "PLANNER_RESPONSE",
      model: "gemini-4-neon-xhigh",
      input_tokens: 40000,
      cache_read_tokens: 200000,
      output_tokens: 500,
    },
    {
      step_index: 2,
      type: "SYSTEM_MESSAGE",
      content: '[CONTEXT_METER] pct=50% tier=soon bar=[█████░░░░░] statut="Dans pas longtemps"',
    },
  ]);

  try {
    // Almost no change (50% -> 50%) in same turn => skipped ({}).
    const skipped = evaluateHookPayload(
      { transcriptPath: file, modelName: "gemini-4-neon-xhigh", hookEventName: "PreInvocation" },
      config
    );
    assert.equal(skipped.skipped, true);
    assert.deepEqual(skipped.output, {});

    // New USER_INPUT starts a fresh turn => must inject again!
    fs.appendFileSync(
      file,
      JSON.stringify({ step_index: 3, type: "USER_INPUT", content: "Question suivante" }) + "\n",
      "utf8"
    );
    const freshTurn = evaluateHookPayload(
      { transcriptPath: file, modelName: "gemini-4-neon-xhigh", hookEventName: "PreInvocation" },
      config
    );
    assert.equal(freshTurn.skipped, false);
    assert.equal(freshTurn.status.restartPct, 50);
    assert.ok(freshTurn.output.injectSteps[0].systemMessage.systemMessage.includes("50%"));
  } finally {
    cleanup(dir);
  }
}

// 4. End-to-end subprocess stdin -> stdout test (exact Antigravity hook contract)
{
  const { dir, file } = writeTempTranscript([
    { step_index: 0, type: "USER_INPUT", content: "Test E2E" },
    {
      step_index: 1,
      type: "PLANNER_RESPONSE",
      model: "gemini-4-hydrogen-tiered-high",
      input_tokens: 12000,
      cache_read_tokens: 123000,
      output_tokens: 1000,
    },
  ]);

  try {
    const payload = JSON.stringify({
      conversationId: "test-conv",
      transcriptPath: file,
      modelName: "gemini-4-hydrogen-tiered-high",
      invocationNum: 0,
      initialNumSteps: 2,
      lastUserInput: "Test E2E",
      hookEventName: "PreInvocation",
      cwd: process.cwd(),
    });

    const proc = spawnSync(process.execPath, [HOOK_SCRIPT], {
      input: payload,
      encoding: "utf8",
    });

    assert.equal(proc.status, 0, `Hook exited with ${proc.status}: ${proc.stderr}`);
    const out = JSON.parse(proc.stdout);
    assert.ok(Array.isArray(out.injectSteps) && out.injectSteps.length === 1);
    const msg = out.injectSteps[0].systemMessage.systemMessage;
    assert.match(msg, /pct=82%/);
    assert.match(msg, /Relancer une nouvelle conversation/);
    console.log("E2E hook output OK:", msg);
  } finally {
    cleanup(dir);
  }
}

console.log("ALL TESTS PASSED!");
