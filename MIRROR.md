# Mirror policy

`basecrawl` is developed under the **Basecrawl** GitHub organization. The BaseIntelligence copy is a public, **read-only mirror**.

| Remote / repo | Role |
| --- | --- |
| [Basecrawl/basecrawl](https://github.com/Basecrawl/basecrawl) | **Canonical** source of truth (issues, PRs, releases) |
| [BaseIntelligence/basecrawl](https://github.com/BaseIntelligence/basecrawl) | **Read-only mirror** for discovery continuity |

crate and npm package names on crates.io / npm remain unchanged (`basecrawl*`, `@basecrawl/*`).

## Git remotes (local)

After clone from either URL, point remotes like this:

```bash
git remote add origin https://github.com/Basecrawl/basecrawl.git   # or: git remote set-url origin ...
git remote add mirror https://github.com/BaseIntelligence/basecrawl.git
```

- `origin` → Basecrawl/basecrawl (canonical)
- `mirror` → BaseIntelligence/basecrawl (read-only mirror)

## Dual push (manual)

There is no secret-token auto-mirror workflow in this tree. Maintainers push both remotes after landing on the tracking branch (`main`):

```bash
git push origin main
git push mirror main
```

Do **not** force-push to rewrite either remote unless an explicit recovery procedure requires it. Do **not** delete the BaseIntelligence mirror.

## GitHub listing text

On BaseIntelligence/basecrawl, keep the repository description/topic signaling that it is a **mirror** of Basecrawl/basecrawl (for example: "Read-only mirror of github.com/Basecrawl/basecrawl"). Prefer Basecrawl for all collaboration.
