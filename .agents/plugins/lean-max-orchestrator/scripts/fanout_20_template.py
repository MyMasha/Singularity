"""Reusable Antigravity `run_workflow` template for up to 20 max-depth parallel workers.

Invoke with:
    run_workflow(
        ScriptPath="<abs>/scripts/fanout_20_template.py",
        Description="Parallel max-depth fan-out",
        Args={
            "tasks": [
                {"id": "T1", "role": "Fix auth bug", "goal": "...", "scope": "src/auth.ts"},
                ...
            ],
            "type_name": "deep-worker",   # or "deep-investigator" / "deep-verifier" / "self"
            "workspace": "inherit",       # use "share" or "branch" if writers may collide
            "max_workers": 20,            # capped at 20
        },
    )
"""

MAX_CAP = 20

REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "task_id": {"type": "string"},
        "status": {"type": "string", "enum": ["DONE", "PARTIAL", "BLOCKED"]},
        "files": {"type": "array", "items": {"type": "string"}},
        "summary": {
            "type": "string",
            "description": "2-3 sentences max, ultra-dense facts only, no raw logs or pasted files.",
        },
        "verified": {
            "type": "string",
            "description": "Exact command/check run and PASS/FAIL result.",
        },
        "blocker": {"type": "string"},
    },
    "required": ["task_id", "status", "files", "summary", "verified", "blocker"],
}

tasks = args.get("tasks", [])
if not isinstance(tasks, list) or len(tasks) == 0:
    raise ValueError("Args['tasks'] must be a non-empty list of task objects.")

max_workers = max(1, min(MAX_CAP, int(args.get("max_workers", MAX_CAP))))
default_type = str(args.get("type_name", "self"))
default_ws = str(args.get("workspace", "inherit"))


def build_prompt(task):
    tid = task.get("id", "task")
    role = task.get("role", "Worker")
    goal = task.get("goal", "")
    scope = task.get("scope", "Projet courant")
    return (
        f"[MAX-DEPTH/LEAN-REPORT] Tâche {tid} — {role}\n"
        f"OBJECTIF : {goal}\n"
        f"PÉRIMÈTRE : {scope}\n"
        "TRAVAIL INTERNE (100% MAX) : n'économise JAMAIS tes propres tokens. "
        "Lis intégralement les fichiers utiles, vérifie types/dépendances/cas limites et exécute les tests/builds.\n"
        "RAPPORT FINAL : renvoie uniquement un objet JSON ultra-compact conforme au schéma "
        "(zéro log brut, zéro code complet recopié)."
    )


waves = [tasks[i : i + max_workers] for i in range(0, len(tasks), max_workers)]
all_reports = []

for wave_idx, wave in enumerate(waves, start=1):
    phase(f"Vague {wave_idx}/{len(waves)} — {len(wave)} sous-agent(s) en parallèle")
    wave_reports = await parallel(
        wave,
        lambda t: agent(
            build_prompt(t),
            schema=REPORT_SCHEMA,
            role=f"{t.get('id', 'T')}: {t.get('role', 'Worker')}",
            type_name=str(t.get("type_name", default_type)),
            workspace=str(t.get("workspace", default_ws)),
        ),
    )
    all_reports.extend(wave_reports)

phase("Rapport consolidé ultra-compact")
done_count = sum(1 for r in all_reports if r["status"] == "DONE")
log(f"TOTAL: {done_count}/{len(all_reports)} DONE")
for r in all_reports:
    files_str = ", ".join(r["files"][:5]) if r["files"] else "aucun"
    blocker = r["blocker"].strip()
    blocker_part = f" | BLOCKER: {blocker}" if blocker and blocker.lower() not in ("aucun", "none", "-") else ""
    log(f"[{r['status']}] {r['task_id']} ({files_str}) — {r['summary']} | Check: {r['verified']}{blocker_part}")
