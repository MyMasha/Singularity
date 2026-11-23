---
name: fanout-20
description: >-
  Orchestre jusqu'à 20 sous-agents haute profondeur en parallèle via
  `run_workflow` (`parallel(...)`) avec un schéma JSON de retour ultra-compact
  obligatoire, afin que l'agent principal ne consomme presque aucun token tout
  en résolvant massivement un problème en parallèle.
---

# Orchestration Parallèle jusqu'à 20 Sous-Agents (`fanout-20`)

Utilise ce skill lorsque le problème de l'utilisateur se découpe en **4 à 20 sous-tâches indépendantes** (ou plus, traitées par **vagues de 20 max**) :
- résoudre plusieurs bugs ou tickets en parallèle ;
- auditer ou refactorer plusieurs fichiers/modules simultanément ;
- explorer plusieurs angles techniques (sécurité, perf, architecture, tests, UX) en parallèle ;
- corriger puis vérifier plusieurs sous-systèmes indépendamment.

*(Pour 1 à 3 sous-tâches simples, appelle directement `invoke_subagent` en parallèle avec `deep-worker`, `deep-investigator` ou `deep-verifier`.)*

## Principes clés

1. **Zéro rationnement dans chaque worker** : chaque prompt de worker lui ordonne de lire en entier, tester à fond et vérifier 100 % dans son propre contexte isolé.
2. **Compression mécanique du retour (`schema`)** : passe un `schema` JSON strict à chaque `agent(...)` dans `run_workflow`. Le tool `finish` force chaque worker à ne renvoyer que des champs courts (statut, fichiers, résumé en 2–3 puces, vérification) — **aucun log brut ne remonte jamais dans l'agent principal**.
3. **Plafond strict de 20 workers simultanés** : si la liste dépasse 20 éléments, découpe-la automatiquement en vagues (`chunk_size = 20`) exécutées séquentiellement par `pipeline(...)`, avec `parallel(...)` à l'intérieur de chaque vague.
4. **Isolation d'écriture obligatoire** :
   - Pour des workers en **lecture / audit** : `workspace="inherit"`.
   - Pour des workers qui **modifient des fichiers disjoints** : `workspace="inherit"` en attribuant explicitement des fichiers sans chevauchement à chaque worker.
   - Pour des workers qui **risquent de toucher les mêmes fichiers ou compiler en parallèle** : `workspace="share"` (ou `"branch"`), puis synthèse/fusion contrôlée.

## Modèle de script `run_workflow` (prêt à adapter)

Consulte aussi [scripts/fanout_20_template.py](../../scripts/fanout_20_template.py) si tu veux réutiliser directement le gabarit.

```python
MAX_WORKERS = 20

REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "task_id": {"type": "string"},
        "status": {"type": "string", "enum": ["DONE", "PARTIAL", "BLOCKED"]},
        "files": {"type": "array", "items": {"type": "string"}},
        "summary": {"type": "string", "description": "Max 2-3 phrases ultra-denses, zéro log brut."},
        "verified": {"type": "string", "description": "Commande exécutée et verdict PASS/FAIL."},
        "blocker": {"type": "string"},
    },
    "required": ["task_id", "status", "files", "summary", "verified", "blocker"],
}

tasks = args["tasks"]  # Liste de dicts: [{"id": "...", "role": "...", "goal": "...", "scope": "..."}]
worker_type = args.get("type_name", "self")  # "self" garantit 100% des outils (shell + écriture + MCP) ; ou "deep-investigator" en lecture seule
ws_mode = args.get("workspace", "inherit")

def make_prompt(t):
    return (
        f"[MAX-DEPTH/LEAN-REPORT] Tâche {t['id']} — {t['role']}\n"
        f"OBJECTIF : {t['goal']}\n"
        f"PÉRIMÈTRE STRICT : {t['scope']}\n"
        "RÈGLE TRAVAIL INTERNE : Travaille à 100% au maximum sans économiser tes propres tokens "
        "(lis tous les fichiers nécessaires en entier, vérifie types/cas limites, lance les tests/builds).\n"
        "RÈGLE RAPPORT FINAL : Retourne uniquement un JSON compact conforme au schéma (zéro code complet, zéro log brut)."
    )

waves = [tasks[i:i + MAX_WORKERS] for i in range(0, len(tasks), MAX_WORKERS)]
all_reports = []

for w_idx, wave in enumerate(waves, start=1):
    phase(f"Vague {w_idx}/{len(waves)} ({len(wave)} workers)")
    reports = await parallel(
        wave,
        lambda t: agent(
            make_prompt(t),
            schema=REPORT_SCHEMA,
            role=f"{t['id']}: {t['role']}",
            type_name=worker_type,
            workspace=ws_mode,
        ),
    )
    all_reports.extend(reports)

phase("Synthèse ultra-compacte")
for r in all_reports:
    files_str = ", ".join(r["files"][:5]) if r["files"] else "aucun"
    blocker_str = f" | BLOCKER: {r['blocker']}" if r["blocker"] and r["blocker"].lower() != "aucun" else ""
    log(f"[{r['status']}] {r['task_id']} ({files_str}) — {r['summary']} | Check: {r['verified']}{blocker_str}")
```

## Règle de synthèse dans l'agent principal

À la réception de la sortie `Logs:` du workflow :
- Ne relis **pas** les fichiers déjà vérifiés par les workers sauf en cas de `BLOCKED` ou de conflit entre 2 workers.
- Si 1 à 3 tâches sont `PARTIAL`/`BLOCKED`, relance une petite vague ciblée uniquement sur ces tâches, suivie d'un `deep-verifier` final.
