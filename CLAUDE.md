# CLAUDE.md

@AGENTS.md

## Worktree-Only Workflow (Enforced)

**All file modifications are blocked in the main checkout.** Work in `.worktrees/<name>/`, created from `origin/main`:

```bash
git fetch origin main
git worktree add .worktrees/<name> -b <branch-name> origin/main
```

## Consumers

None yet. The planned rollout (P6, `/rollout-gem`) goes first to `nutripod-web` and `jumpdrive-web`, then `fundbright-web` and `luminality-web`, then `sidekick-web` on its own moneta instance. The canonical consumer matrix lives in the workspace `/rollout-gem` skill's `SKILL.md`.
