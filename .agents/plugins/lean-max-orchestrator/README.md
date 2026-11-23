# Lean Main / Max Sub-Agents (x20) — Module Antigravity

Plugin officiel pour **Google Antigravity** conçu pour maximiser l'efficacité tout en gardant la conversation principale ultra-légère en tokens :

- **Agent principal (ultra-léger)** : n'absorbe ni gros fichiers ni logs bruts ; rédige des demandes chirurgicales et ne reçoit que des rapports ultra-compacts (≤ 15–18 lignes ou JSON strict), pour faire durer la conversation principale beaucoup plus longtemps.
- **Sous-agents (jusqu'à 20 en parallèle, effort 100 % maximal)** : chaque sous-agent travaille dans sa propre fenêtre de contexte isolée **sans jamais économiser ses propres tokens** (lecture intégrale, dépendances, cas limites, builds/tests complets), puis compresse uniquement son rapport final.

## Composants inclus

1. **Règle toujours active (`rules/AGENTS.md`)** : sépare clairement le **Rôle A (Agent Principal : minimum de tokens + délégation jusqu'à 20 sous-agents)** du **Rôle B (Sous-Agent : 100 % effort max interne + rapport final compact)**.
2. **3 sous-agents dédiés (`agents/`)** :
   - `deep-worker` — implémentation et correction complètes à profondeur maximale
   - `deep-investigator` — enquête, debug racine et audit exhaustifs
   - `deep-verifier` — QA, tests, builds et cas limites à 100 %
3. **Hook `PreToolUse` (`hooks.json` + `scripts/enforce-subagent-contract.mjs`)** : vérifie automatiquement chaque appel `invoke_subagent` (hors `browser` et `image-generator`) et injecte le contrat `[MAX-DEPTH/LEAN-REPORT]` si l'agent principal a oublié de le rappeler.
4. **Skill `fanout-20` (`skills/fanout-20/SKILL.md` + `scripts/fanout_20_template.py`)** : lance de **4 à 20 sous-agents en parallèle** via `run_workflow` (en vagues de 20 max si plus de 20 tâches) avec un **schéma JSON strict** imposé sur `finish` pour empêcher toute pollution de tokens dans l'agent principal.

## Installation (local & remote)

- **Global (ce PC + Antigravity Remote Control mobile/navigateur)** :
  ```powershell
  .\install.ps1
  ```
- **Remote SSH (`Connect to SSH Host`)** :
  ```powershell
  .\install.ps1 -SshHost "utilisateur@mon-serveur"
  ```
- **Projet Git / Remote Agents Cloud** :
  ```powershell
  .\install.ps1 -Workspace "C:\chemin\vers\ton\repo"
  ```

## Personnalisation (`config.json`)

- `maxConcurrentSubagents` : plafond de parallélisme (défaut : `20`)
- `maxReportLines` : limite de lignes du rapport final renvoyé à l'agent principal (défaut : `18`)
- `excludedSubagentTypes` : sous-agents spécialisés non modifiés par le hook (`browser`, `image-generator`)

## Vérification

```powershell
node scripts/test-orchestrator.mjs
agy plugin validate . --strict
```
