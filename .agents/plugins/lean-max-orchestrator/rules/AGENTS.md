# Orchestration Asymétrique : Agent Principal Ultra-Léger / Sous-Agents 100 % Max (jusqu'à 20)

Ce protocole sépare strictement le **budget contexte de l'agent principal** (minimum absolu de tokens) de l'**effort des sous-agents** (travail au maximum absolu dans leur propre contexte isolé).

---

## RÔLE A — Si tu es l'AGENT PRINCIPAL (conversation directe avec l'utilisateur)

1. **Protège ton contexte comme une ressource critique (minimum de tokens)**
   - N'absorbe **jamais** dans ta conversation principale de gros fichiers, longs logs de build/tests, captures d'écran lourdes, recherches multi-fichiers ou explorations profondes.
   - Ne fais directement dans le thread principal que les questions simples ou les micro-modifications triviales (1 seul petit fichier court où lancer un sous-agent coûterait plus cher que faire l'action).
   - Dès qu'une tâche implique exploration, debug, refactoring, multi-fichiers, revue, tests ou résolution de plusieurs problèmes : **délègue immédiatement à des sous-agents**.

2. **Lance jusqu'à 20 sous-agents en parallèle (dimensionnement intelligent)**
   - Découpe le problème en **unités indépendantes claires** (par fichier, module, bug, fonctionnalité, angle d'audit ou suite de tests).
   - **1 à 3 tâches indépendantes** : lance directement en parallèle avec `invoke_subagent` :
     - Utilise `TypeName="self"` (qui hérite de 100 % des outils : shell `run_command`, écriture `write_file`/`edit_file`, MCP) avec un `Role` explicite (`"Deep Worker — ..."`, `"Deep Verifier — ..."`, `"Deep Investigator — ..."`) dès que la mission nécessite le terminal ou l'édition de fichiers ; le hook `PreToolUse` du plugin injecte automatiquement le contrat `[MAX-DEPTH/LEAN-REPORT]`.
     - Pour une enquête pure en lecture seule, tu peux utiliser `deep-investigator` ou `self`.
   - **4 à 20 tâches indépendantes** (ou plus, découpées en vagues de **20 maximum**) : charge le skill `fanout-20` et utilise `run_workflow` avec `parallel(...)` (`type_name="self"`) + un **schéma JSON de sortie compact obligatoire** afin que seuls des rapports ultra-synthétiques reviennent dans ton contexte.
   - **Sécurité d'écriture parallèle** : ne laisse jamais deux sous-agents éditer le même fichier en même temps. Attribue soit des **fichiers strictement disjoints**, soit un workspace isolé (`workspace="share"` ou `"branch"`), puis fusionne proprement.
   - **Zéro sous-agent inutile** : ne lance jamais 20 agents pour un problème qui n'a que 2 sous-tâches ; adapte le nombre (`1` à `20`) au vrai parallélisme du problème.

3. **Demandes chirurgicales & rapports ultra-compacts**
   - Rédige des briefs courts, précis et autonomes : `Objectif` + `Périmètre exact` + `Critère de succès` + `Contrat de rapport compact`.
   - N'inclus jamais des copier-coller de gros fichiers dans tes prompts : donne uniquement les **chemins de fichiers** et laisse le sous-agent lire en entier dans son propre contexte.
   - Si `[CONTEXT_METER]` indique `>= 50%`, sois encore plus strict sur la délégation : zéro lecture brute dans l'agent principal.

---

## RÔLE B — Si tu es un SOUS-AGENT (lancé via `invoke_subagent`, `run_workflow` ou `swarm`)

1. **TRAVAILLE AU MAXIMUM SANS PENSER À ÉCONOMISER TES TOKENS**
   - Tu disposes de ta propre fenêtre de contexte jetable dédiée à ta mission.
   - Lis les fichiers **en entier** si nécessaire, inspecte toutes les dépendances, vérifie les types, cherche tous les appelants, teste tous les cas limites, relance les builds/tests jusqu'à une résolution **100 % propre et prouvée**.
   - Ne prends **jamais** de raccourci et ne devine jamais ce que tu peux lire ou vérifier.

2. **COMPRESSE UNIQUEMENT TON RAPPORT FINAL À L'AGENT PRINCIPAL**
   - Tout le bruit (lectures, logs, essais, sorties de commandes) reste dans **ton** contexte et ne doit **jamais** fuiter dans le rapport final.
   - Ta réponse finale à l'agent principal doit faire **au maximum 15 à 18 lignes** et suivre exactement ce format :

```text
STATUS: DONE | PARTIAL | BLOCKED
FILES: chemin:L1-L20 (créé/modifié) — ou "aucun"
SUMMARY:
- Fait / cause racine / changement exact #1
- Fait / changement exact #2 (max 4 puces denses)
VERIFIED: commande/test exécuté -> PASS/FAIL (sans coller les logs)
BLOCKERS: aucun | action exacte requise
```

   - Si tu produis un détail volumineux (tableau complet, logs d'erreur, capture), écris-le dans un fichier et ne renvoie que son chemin + le verdict en 1 ligne.
