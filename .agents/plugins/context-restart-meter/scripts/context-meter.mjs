#!/usr/bin/env node
/**
 * Context Restart Meter — Antigravity PreInvocation Hook & Diagnostic CLI
 *
 * Reads Antigravity's real transcript.jsonl token usage (input_tokens +
 * cache_read_tokens + output_tokens + post-response delta + CHECKPOINT count)
 * and injects a compact [CONTEXT_METER] telemetry message before the model
 * answers so the AI reports the exact restart percentage at the end of every
 * message:
 *   -  0% - 49% : OK (pas besoin de relancer)
 *   - 50% - 79% : Dans pas longtemps
 *   - 80% - 99% : Relancer une nouvelle conversation
 *   - 100%      : Il faut absolument relancer une nouvelle conversation !
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PLUGIN_ROOT = path.resolve(__dirname, "..");

const DEFAULT_CONFIG = {
  defaultMaxTokens: 200000,
  baseSystemTokens: 28000,
  postCheckpointBaseTokens: 42000,
  charsPerToken: 3.8,
  minDeltaPctToReinject: 3,
  modelBudgets: [
    { pattern: "neon", maxTokens: 480000 },
    { pattern: "gemini-4-pro", maxTokens: 480000 },
    { pattern: "gemini-3", maxTokens: 480000 },
    { pattern: "gemini-2\\.5", maxTokens: 480000 },
    { pattern: "carbon", maxTokens: 250000 },
    { pattern: "hydrogen", maxTokens: 165000 },
    { pattern: "claude", maxTokens: 165000 },
    { pattern: "opus", maxTokens: 165000 },
    { pattern: "sonnet", maxTokens: 165000 },
    { pattern: "gpt-5", maxTokens: 240000 },
    { pattern: "gpt-4", maxTokens: 120000 },
  ],
  thresholds: {
    soon: 50,
    restart: 80,
    critical: 100,
  },
  compactionWeight: {
    enabled: true,
    firstCheckpointFloorPct: 55,
    secondCheckpointFloorPct: 80,
    extraCheckpointBonusPct: 10,
  },
};

export function loadConfig(configPath = path.join(PLUGIN_ROOT, "config.json")) {
  try {
    if (fs.existsSync(configPath)) {
      const parsed = JSON.parse(fs.readFileSync(configPath, "utf8"));
      return {
        ...DEFAULT_CONFIG,
        ...parsed,
        thresholds: { ...DEFAULT_CONFIG.thresholds, ...(parsed.thresholds || {}) },
        compactionWeight: {
          ...DEFAULT_CONFIG.compactionWeight,
          ...(parsed.compactionWeight || {}),
        },
        modelBudgets: Array.isArray(parsed.modelBudgets)
          ? parsed.modelBudgets
          : DEFAULT_CONFIG.modelBudgets,
      };
    }
  } catch {
    // Fall back silently to defaults so hooks never fail.
  }
  return DEFAULT_CONFIG;
}

export function resolveMaxTokens(modelName, config) {
  const name = String(modelName || "").trim();
  if (name && name.toLowerCase() !== "auto") {
    for (const entry of config.modelBudgets || []) {
      try {
        if (new RegExp(entry.pattern, "i").test(name) && Number(entry.maxTokens) > 0) {
          return Number(entry.maxTokens);
        }
      } catch {
        // Ignore malformed user regex.
      }
    }
  }
  return Number(config.defaultMaxTokens) || 200000;
}

export function estimateTokensFromText(text, charsPerToken = 3.8) {
  if (!text) return 0;
  return Math.ceil(String(text).length / Math.max(1, charsPerToken));
}

export function formatTokensShort(tokens) {
  if (tokens < 1000) return `${tokens}`;
  return `${Math.round(tokens / 1000)}k`;
}

export function renderBar(pct, width = 10) {
  const clamped = Math.max(0, Math.min(100, Math.round(pct)));
  const filled = Math.max(0, Math.min(width, Math.round((clamped / 100) * width)));
  return `[${"█".repeat(filled)}${"░".repeat(width - filled)}]`;
}

function safeParseJsonLine(line) {
  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
}

export function analyzeTranscript(transcriptPath, payload = {}, config = loadConfig()) {
  const charsPerToken = Number(config.charsPerToken) || 3.8;
  let lines = [];

  if (transcriptPath && fs.existsSync(transcriptPath)) {
    const raw = fs.readFileSync(transcriptPath, "utf8");
    lines = raw.split(/\r?\n/).filter((l) => l.length > 0);
  }

  let checkpointCount = 0;
  let lastCheckpointLineIdx = -1;
  let lastUserLineIdx = -1;
  let hasExplicitUserInput = false;
  let hasAgentMessage = false;
  let lastMeterLineIdx = -1;
  let lastMeterLine = null;
  const plannerLineIndices = [];

  // Fast first pass: only JSON.parse the rare lines we actually need.
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.includes('"PLANNER_RESPONSE"')) {
      plannerLineIndices.push(i);
    }
    if (line.includes('"CHECKPOINT"')) {
      const obj = safeParseJsonLine(line);
      if (obj && obj.type === "CHECKPOINT") {
        checkpointCount++;
        lastCheckpointLineIdx = i;
      }
    }
    if (line.includes('"USER_INPUT"')) {
      const obj = safeParseJsonLine(line);
      if (obj && obj.type === "USER_INPUT") {
        lastUserLineIdx = i;
        if (obj.source === "USER_EXPLICIT") {
          hasExplicitUserInput = true;
        }
      }
    }
    if (!hasAgentMessage && line.includes("[Message] timestamp=") && line.includes("sender=")) {
      hasAgentMessage = true;
    }
    if (line.includes("[CONTEXT_METER]")) {
      const obj = safeParseJsonLine(line);
      if (obj && obj.type === "SYSTEM_MESSAGE" && typeof obj.content === "string") {
        if (obj.content.includes("[CONTEXT_METER]")) {
          lastMeterLineIdx = i;
          lastMeterLine = obj.content;
        }
      }
    }
  }

  const isSubagentSession =
    !hasExplicitUserInput &&
    !String(payload.lastUserInput || "").trim() &&
    (hasAgentMessage || (lines.length > 0 && lastUserLineIdx === -1));

  // Find the most recent PLANNER_RESPONSE containing token metrics.
  let lastValidPlannerLineIdx = -1;
  let lastPromptTokens = 0;
  let lastOutputTokens = 0;
  let detectedModel = "";

  for (let idx = plannerLineIndices.length - 1; idx >= 0; idx--) {
    const lineIdx = plannerLineIndices[idx];
    const obj = safeParseJsonLine(lines[lineIdx]);
    if (!obj || obj.type !== "PLANNER_RESPONSE") continue;
    const inp = Number(obj.input_tokens) || 0;
    const cacheRead = Number(obj.cache_read_tokens) || 0;
    const out = Number(obj.output_tokens) || 0;
    if (!detectedModel && obj.model) {
      detectedModel = String(obj.model);
    }
    if (inp + cacheRead > 0) {
      lastValidPlannerLineIdx = lineIdx;
      lastPromptTokens = inp + cacheRead;
      lastOutputTokens = out;
      if (obj.model) detectedModel = String(obj.model);
      break;
    }
  }

  const effectiveModel = detectedModel || String(payload.modelName || "");
  const maxTokens = resolveMaxTokens(effectiveModel, config);

  // Estimate tokens appended AFTER the last measured PLANNER_RESPONSE (or CHECKPOINT).
  const tailStart = Math.max(lastValidPlannerLineIdx, lastCheckpointLineIdx) + 1;
  let deltaTokens = 0;
  for (let i = tailStart; i < lines.length; i++) {
    const obj = safeParseJsonLine(lines[i]);
    if (!obj) continue;
    if (typeof obj.content === "string") {
      deltaTokens += estimateTokensFromText(obj.content, charsPerToken);
    }
    if (Array.isArray(obj.tool_calls) && obj.tool_calls.length > 0) {
      deltaTokens += estimateTokensFromText(JSON.stringify(obj.tool_calls), charsPerToken);
    }
  }

  let activeTokens;
  let measurementSource;

  if (lastCheckpointLineIdx > lastValidPlannerLineIdx) {
    activeTokens = (Number(config.postCheckpointBaseTokens) || 42000) + deltaTokens;
    measurementSource = "post-checkpoint";
  } else if (lastValidPlannerLineIdx >= 0) {
    activeTokens = lastPromptTokens + lastOutputTokens + deltaTokens;
    measurementSource = "transcript";
  } else {
    const userInputTokens =
      lastUserLineIdx >= 0 ? 0 : estimateTokensFromText(payload.lastUserInput || "", charsPerToken);
    activeTokens = (Number(config.baseSystemTokens) || 28000) + deltaTokens + userInputTokens;
    measurementSource = "initial-estimate";
  }

  // Extract previous [CONTEXT_METER] emitted during the current user turn (for deduplication).
  let previousTurnMeter = null;
  if (lastMeterLine && lastMeterLineIdx > lastUserLineIdx) {
    const match = lastMeterLine.match(/\[CONTEXT_METER\]\s+pct=(\d+)%\s+tier=([a-z]+)/);
    if (match) {
      previousTurnMeter = {
        pct: Number(match[1]),
        tier: match[2],
      };
    }
  }

  return {
    model: effectiveModel || "default",
    activeTokens,
    maxTokens,
    checkpointCount,
    measurementSource,
    previousTurnMeter,
    isSubagentSession,
    lastValidPlannerLineIdx,
    lastUserLineIdx,
    lastMeterLineIdx,
  };
}

export function computeStatus(metrics, config = loadConfig()) {
  const { activeTokens, maxTokens, checkpointCount } = metrics;
  const rawActivePct = maxTokens > 0 ? Math.round((activeTokens / maxTokens) * 100) : 0;
  const activePct = Math.max(activeTokens > 0 ? 1 : 0, Math.min(100, rawActivePct));

  let restartPct = activePct;
  const cw = config.compactionWeight || DEFAULT_CONFIG.compactionWeight;

  if (cw.enabled && checkpointCount > 0) {
    if (checkpointCount === 1) {
      const floor = Number(cw.firstCheckpointFloorPct) || 55;
      restartPct = Math.min(
        100,
        Math.max(activePct, floor + Math.round((activePct * (100 - floor)) / 100))
      );
    } else {
      const base =
        (Number(cw.secondCheckpointFloorPct) || 80) +
        (checkpointCount - 2) * (Number(cw.extraCheckpointBonusPct) || 10);
      restartPct = Math.min(100, Math.max(activePct, base + Math.round(activePct * 0.25)));
    }
  }

  const t = config.thresholds || DEFAULT_CONFIG.thresholds;
  const soon = Number(t.soon) || 50;
  const restart = Number(t.restart) || 80;
  const critical = Number(t.critical) || 100;

  let tier;
  let label;
  if (restartPct >= critical) {
    tier = "critical";
    label = "Il faut absolument relancer une nouvelle conversation !";
  } else if (restartPct >= restart) {
    tier = "restart";
    label = "Relancer une nouvelle conversation";
  } else if (restartPct >= soon) {
    tier = "soon";
    label = "Dans pas longtemps";
  } else {
    tier = "ok";
    label = "OK (pas besoin de relancer)";
  }

  const bar = renderBar(restartPct, 10);
  const tokenPart = `${formatTokensShort(activeTokens)} / ${formatTokensShort(maxTokens)} tokens`;
  const compactionPart =
    checkpointCount > 0 ? `, déjà compactée ${checkpointCount}×` : "";
  const estimatePart =
    metrics.measurementSource === "initial-estimate" ? ", estimation initiale" : "";
  const details = `${tokenPart}${compactionPart}${estimatePart}`;

  const footerMarkdown = `**Relance conversation : \`${restartPct}%\`** \`${bar}\` — **${label}** *(${details})*`;

  return {
    activePct,
    restartPct,
    tier,
    label,
    bar,
    details,
    footerMarkdown,
  };
}

export function evaluateHookPayload(payload, config = loadConfig()) {
  const metrics = analyzeTranscript(payload?.transcriptPath, payload, config);
  const status = computeStatus(metrics, config);

  // Never inject user-facing restart footers into background sub-agent transcripts.
  if (metrics.isSubagentSession) {
    return { skipped: true, metrics, status, output: {} };
  }

  const minDelta = Number(config.minDeltaPctToReinject ?? 3);
  if (
    metrics.previousTurnMeter &&
    metrics.previousTurnMeter.tier === status.tier &&
    Math.abs(status.restartPct - metrics.previousTurnMeter.pct) < minDelta
  ) {
    return { skipped: true, metrics, status, output: {} };
  }

  const systemText =
    `[CONTEXT_METER] pct=${status.restartPct}% tier=${status.tier} bar=${status.bar} ` +
    `statut="${status.label}" details="${status.details}" | ` +
    `À la toute fin de ta réponse finale à l'utilisateur, ajoute une ligne --- puis exactement : ` +
    status.footerMarkdown;

  return {
    skipped: false,
    metrics,
    status,
    output: {
      injectSteps: [
        {
          systemMessage: {
            systemMessage: systemText,
          },
        },
      ],
    },
  };
}

async function readStdinText() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
  }
  return Buffer.concat(chunks).toString("utf8").trim();
}

async function main() {
  const args = process.argv.slice(2);
  const config = loadConfig();

  // Optional CLI diagnostic mode: node scripts/context-meter.mjs --diagnose <transcriptPath> [--model <name>]
  if (args.includes("--diagnose")) {
    const idx = args.indexOf("--diagnose");
    const transcriptPath = args[idx + 1] || "";
    const modelIdx = args.indexOf("--model");
    const modelName = modelIdx >= 0 ? args[modelIdx + 1] : "";
    const metrics = analyzeTranscript(transcriptPath, { modelName }, config);
    const status = computeStatus(metrics, config);
    console.log(
      JSON.stringify(
        {
          model: metrics.model,
          measurementSource: metrics.measurementSource,
          activeTokens: metrics.activeTokens,
          maxTokens: metrics.maxTokens,
          activePct: status.activePct,
          checkpointCount: metrics.checkpointCount,
          restartPct: status.restartPct,
          tier: status.tier,
          label: status.label,
          footerPreview: status.footerMarkdown,
        },
        null,
        2
      )
    );
    return;
  }

  // Standard Antigravity PreInvocation hook mode (JSON on stdin -> JSON on stdout).
  try {
    const raw = await readStdinText();
    const payload = raw ? JSON.parse(raw) : {};
    const result = evaluateHookPayload(payload, config);
    process.stdout.write(`${JSON.stringify(result.output)}\n`);
  } catch {
    // Never break the Antigravity agent loop if stdin/transcript is unreadable.
    process.stdout.write("{}\n");
  }
}

const isDirectRun =
  process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;

if (isDirectRun) {
  main();
}
