---
name: context-status
description: >-
  Affiche un diagnostic détaillé du remplissage du contexte de la conversation
  (tokens exacts, modèle, compactions, seuils 50% / 80% / 100%) et génère un
  résumé de reprise propre quand il faut relancer une nouvelle conversation.
---

# Context Status & Handoff

Utilise ce skill lorsque l'utilisateur demande :
- un **diagnostic détaillé** du remplissage de la conversation actuelle ;
- un **résumé de reprise (handoff)** prêt à copier-coller dans une nouvelle conversation (surtout à `80%` ou `100%`) ;
- de **modifier les seuils** (`50%`, `80%`, `100%`) ou les budgets de tokens par modèle dans `config.json`.

## 1. Diagnostic détaillé

Exécute le script de diagnostic intégré sur le transcript courant :

```bash
node scripts/context-meter.mjs --diagnose "<chemin_du_transcript.jsonl>"
```

Présente ensuite un récapitulatif clair en français :
- Modèle détecté et plafond utile (`maxTokens`)
- Tokens actifs mesurés (`activeTokens`) et pourcentage brut (`activePct%`)
- Nombre de compactions automatiques déjà subies (`checkpointCount`)
- Pourcentage final de relance (`restartPct%`) et verdict (`OK`, `Dans pas longtemps`, `Relancer`, ou `Il faut absolument relancer !`)

## 2. Résumé de reprise (Handoff pour nouvelle conversation)

Quand l'utilisateur veut relancer une nouvelle conversation propre, génère un bloc Markdown autonome et compact contenant :
1. **Objectif en cours** (1–2 phrases)
2. **Ce qui a déjà été fait** (liste courte + chemins des fichiers créés/modifiés)
3. **Décisions importantes & contraintes**
4. **Prochaine étape exacte à exécuter**

Termine en rappelant qu'il suffit de copier-coller ce bloc dans une nouvelle conversation (ou d'utiliser `/compact` pour compresser sur place).
