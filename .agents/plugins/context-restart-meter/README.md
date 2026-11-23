# Context Restart Meter — Module Antigravity

Module (plugin) officiel pour **Google Antigravity** qui mesure le remplissage **réel** de la fenêtre de contexte de ta conversation et affiche automatiquement, à la fin de chaque réponse de l'IA, le pourcentage indiquant s'il faut relancer une nouvelle conversation.

## Paliers de relance

| Pourcentage | Statut affiché | Action recommandée |
| :--- | :--- | :--- |
| `0% – 49%` | **OK (pas besoin de relancer)** | Conversation fluide, continue normalement. |
| `50% – 79%` | **Dans pas longtemps** | La conversation commence à se remplir : prépare-toi à relancer bientôt. |
| `80% – 99%` | **Relancer une nouvelle conversation** | Contexte presque plein : relance une nouvelle conversation (ou lance `/compact`). |
| `100%` | **Il faut absolument relancer une nouvelle conversation !** | Contexte saturé : risque élevé de perte de détails ou de compaction forcée. |

Exemple en fin de message :

> ---
> **Relance conversation : `82%`** `[████████░░]` — **Relancer une nouvelle conversation** *(394k / 480k tokens)*

## Comment ça fonctionne ?

Le plugin combine trois composants natifs Antigravity :

1. **Hook `PreInvocation` (`hooks.json` + `scripts/context-meter.mjs`)** : avant chaque tour, lit directement les vrais compteurs de tokens (`input_tokens + cache_read_tokens + output_tokens`), le delta depuis la dernière réponse et le nombre de compactions (`CHECKPOINT`) déjà subies dans `transcript.jsonl`, puis transmet la mesure exacte à l'agent (dédupliquée dans un même tour pour ne pas gaspiller de tokens).
2. **Règle toujours active (`rules/AGENTS.md`)** : impose à l'IA d'afficher cette jauge exacte en une ligne propre à la toute fin de chaque réponse finale.
3. **Skill à la demande (`skills/context-status/SKILL.md`)** : permet de demander un diagnostic détaillé ou un **résumé de reprise (handoff)** prêt à coller dans une nouvelle conversation.

## Installation

### Option 1 — Installation globale (toutes tes conversations Antigravity)

Sous Windows (PowerShell) :

```powershell
.\install.ps1
```

Sous macOS / Linux :

```bash
bash ./install.sh
```

Cela copie le plugin dans `~/.gemini/config/plugins/context-restart-meter/`. Tu pourras ensuite l'activer/désactiver en un clic depuis la page **Customizations / Plugins** d'Antigravity.

### Option 2 — Installation limitée à un seul projet (et Remote Agents Cloud)

```powershell
.\install.ps1 -Workspace "C:\chemin\vers\ton\projet"
```

Commiter `.agents/plugins/context-restart-meter/` dans un dépôt Git permet également aux **Remote Agents (VM Cloud)** de charger automatiquement le module sur ce projet.

### Option 3 — Installation en Remote SSH (`Connect to SSH Host`)

```powershell
.\install.ps1 -SshHost "utilisateur@mon-serveur"
```

> **Note Remote Control (mobile / navigateur)** : aucune manipulation supplémentaire n'est nécessaire. L'installation globale (`Option 1`) s'applique automatiquement en Remote Control puisque l'agent s'exécute sur ce PC.

## Personnalisation (`config.json`)

Tu peux ajuster les seuils ou la limite de tokens par modèle directement dans `config.json` :

- `thresholds`: `soon` (`50`), `restart` (`80`), `critical` (`100`)
- `modelBudgets`: plafond utile de tokens avant compaction automatique selon le modèle (ex. `480000` pour Gemini 4 Neon, `165000` pour les modèles 200k, `200000` par défaut)
- `compactionWeight`: pondération automatique si Antigravity a déjà effectué une ou plusieurs compactions (`CHECKPOINT`), afin que la jauge ne retombe jamais artificiellement à 10 % sur une conversation déjà longue.

## Vérification & Tests

```powershell
node scripts/test-meter.mjs
agy plugin validate . --strict
```
