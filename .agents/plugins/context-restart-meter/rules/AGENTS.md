# Indicateur de relance de conversation (Context Restart Meter)

À la **toute fin de chaque réponse finale** envoyée à l'utilisateur, tu DOIS ajouter un séparateur `---` suivi d'une ligne compacte indiquant le pourcentage de nécessité de relancer une nouvelle conversation.

## Source de la mesure

1. Recherche le message système `[CONTEXT_METER]` le plus récent dans la conversation. Il est calculé automatiquement avant chaque tour à partir du vrai nombre de tokens du transcript et des éventuelles compactions déjà effectuées.
2. Recopie **exactement** le pourcentage (`pct`), la jauge (`bar`), le statut (`statut`) et le détail tokens/compactions fournis par ce `[CONTEXT_METER]`. Ne modifie pas le chiffre et n'invente jamais un pourcentage différent.
3. Si aucun `[CONTEXT_METER]` n'est présent (par exemple lors d'un tout premier message sans hook), estime prudemment le remplissage à partir de la longueur de la conversation et précise `(estimation)`.

## Grille des seuils de relance

| Pourcentage | Statut affiché | Signification |
| :--- | :--- | :--- |
| `0% – 49%` | **OK (pas besoin de relancer)** | Conversation encore légère et fluide. |
| `50% – 79%` | **Dans pas longtemps** | La conversation commence à se remplir : prévoir de relancer bientôt. |
| `80% – 99%` | **Relancer une nouvelle conversation** | La conversation est presque pleine : il est recommandé de relancer maintenant (ou d'utiliser `/compact`). |
| `100%` | **Il faut absolument relancer une nouvelle conversation !** | Contexte saturé : risque élevé de perte de détails ou de compaction forcée. |

## Format obligatoire en fin de message

Termine toujours ta réponse finale par exactement ce bloc :

```markdown
---
**Relance conversation : `<PCT>%`** `<BAR>` — **<STATUT>** *(<DETAILS>)*
```

Exemples :
- `**Relance conversation : 18%** [██░░░░░░░░] — **OK (pas besoin de relancer)** *(86k / 480k tokens)*`
- `**Relance conversation : 54%** [█████░░░░░] — **Dans pas longtemps** *(259k / 480k tokens)*`
- `**Relance conversation : 84%** [████████░░] — **Relancer une nouvelle conversation** *(403k / 480k tokens)*`
- `**Relance conversation : 100%** [██████████] — **Il faut absolument relancer une nouvelle conversation !** *(482k / 480k tokens)*`

## Règles de sobriété

- N'ajoute **pas** ce pied de page si l'utilisateur demande explicitement une sortie brute uniquement destinée à une machine (ex. « renvoie uniquement du JSON brut sans aucun texte autour »).
- À partir de `80%`, tu peux ajouter en une courte phrase que tu peux générer un résumé de reprise si l'utilisateur souhaite ouvrir une nouvelle conversation.
