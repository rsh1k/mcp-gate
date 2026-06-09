# Publishing mcp-gate

Two parts: (A) get the repo onto GitHub cleanly, and (B) the exact PyPI Trusted
Publishing click-path so releases need no stored token. For the release
mechanics themselves (build, tag, GHCR), see `RELEASING.md`.

---

## A. Publish to GitHub

### A0. One-time prep before the first push

```bash
cd mcp-gate

# Make sure no secrets or local audit logs get committed. .gitignore already
# excludes *.jsonl, dist/, build/, __pycache__, .env — double check:
git status --porcelain   # nothing sensitive should appear

# Set the placeholder repo URL in these files to your real handle FIRST:
#   - Dockerfile (LABEL ... image.source)
#   - README.md  (clone URL, ghcr image path, repo link)
#   - .github/workflows/release.yml uses ${{ github.repository }} automatically
grep -rn "USER/mcp-gate\|<you>\|<github-username>" . --include='*.md' --include='Dockerfile' --include='*.yml'
```

Replace every `USER` / `<you>` / `<github-username>` placeholder with your
GitHub username (or org).

### A1. Initialize and commit

```bash
git init
git add .
git commit -m "Initial public release: mcp-gate v0.3.0"
git branch -M main
```

### A2. Create the GitHub repo and push

**Option 1 — GitHub CLI (fastest):**

```bash
# Install gh from https://cli.github.com if needed, then:
gh auth login
gh repo create mcp-gate --public --source=. --remote=origin \
  --description "A policy firewall for AI-agent tool calls (MCP). Allow/deny/redact every tool call, with tamper-evident audit logging and NIST/OWASP control mapping." \
  --push
```

**Option 2 — web UI:** create an empty public repo named `mcp-gate` at
<https://github.com/new> (do **not** add a README/license — you already have
them), then:

```bash
git remote add origin https://github.com/rsh1k/mcp-gate.git
git push -u origin main
```

### A3. Set the repo description and topics

Topics power discovery. On the repo page, click the gear next to "About" and add
the description plus these topics:

```
mcp  ai-agents  ai-security  agentic-ai  policy-engine  governance
nist  owasp  llm  model-context-protocol  prompt-injection  security
```

### A4. Recommended repo settings

- **Settings → General → Features:** enable Issues and Discussions.
- **Settings → Code security:** enable **Private vulnerability reporting**
  (your `SECURITY.md` directs people there) and Dependabot alerts.
- **Settings → Branches → Add branch ruleset** for `main`:
  - Require a pull request before merging.
  - Require status checks to pass → select the `tests` checks from `ci.yml`
    (they appear after the first CI run, so push once, let CI run, then add).
- **Settings → Actions → General:** allow GitHub Actions (needed for CI and the
  release workflow).

### A5. Confirm CI is green

After the push, open the **Actions** tab. The `tests` workflow should run on
Python 3.10/3.11/3.12 and pass (37+ unit tests, 20-sample harness, policy
check). Fix anything red before announcing.

### A6. Cut the first release (tag)

```bash
git tag -a v0.3.0 -m "mcp-gate v0.3.0"
git push origin v0.3.0
```

Then **Releases → Draft a new release**, choose the `v0.3.0` tag, title it
`v0.3.0`, and paste the matching `CHANGELOG.md` section as the notes. Publishing
the release is also what triggers `release.yml` (PyPI + GHCR) — so set up Trusted
Publishing (Part B) *before* you push the tag, or the PyPI job will fail.

---

## B. PyPI Trusted Publishing click-path (no stored token)

Trusted Publishing lets your GitHub Action publish to PyPI via short-lived OIDC
credentials, so you never store a PyPI token in GitHub secrets. Set it up once.

### B1. Reserve the name (recommended)

Names are first-come on PyPI. Check <https://pypi.org/project/mcp-gate/>. If it's
taken, rename in `pyproject.toml` (`[project].name`) and the README before going
further. If it's free, you can either do a first manual upload (see
`RELEASING.md` §3) to claim it, or use "pending publisher" below to claim it via
the first automated publish.

### B2. Add the trusted publisher on PyPI

1. Log in to <https://pypi.org> and go to **Your projects**.
   - If the project already exists: open it → **Settings** → **Publishing** →
     **Add a new publisher**.
   - If it doesn't exist yet: go to **Your account → Publishing → Add a pending
     publisher** (this pre-authorizes the first automated upload to create it).
2. Choose **GitHub** as the publisher and fill in **exactly**:
   - **Owner:** your GitHub username or org (e.g. `rsh1k`)
   - **Repository name:** `mcp-gate`
   - **Workflow name:** `release.yml`  ← must match the file in
     `.github/workflows/`
   - **Environment name:** leave blank, *unless* you add an environment (see
     B3 — recommended), in which case enter that environment's name.
3. Save.

### B3. (Recommended) Add a protected `pypi` environment

This adds a manual gate so a tag push can't auto-publish without approval.

1. GitHub → **Settings → Environments → New environment** → name it `pypi`.
2. Add yourself as a **Required reviewer** (optional but recommended).
3. In `.github/workflows/release.yml`, add the environment to the `pypi` job:

   ```yaml
   pypi:
     needs: test
     runs-on: ubuntu-latest
     environment: pypi          # <-- add this line
     permissions:
       id-token: write
   ```

4. Back on PyPI (B2), set the **Environment name** to `pypi` so it matches.

### B4. Verify the wiring

The `release.yml` `pypi` job already uses `pypa/gh-action-pypi-publish@release/v1`
with `id-token: write` and no `password:` — that's the Trusted Publishing path.
Nothing else to configure. On the next tag push:

1. CI tests run → must pass.
2. The `pypi` job builds, `twine check`s, and publishes via OIDC.
3. If you added the `pypi` environment, approve the run when prompted.

### B5. Confirm

```bash
pip install mcp-gate            # from a clean machine/venv
mcp-gate controls
```

---

## Sequencing (do this in order)

1. Replace placeholders (A0) → push to GitHub (A1–A2) → set topics/settings (A3–A4).
2. Let CI go green (A5).
3. Set up PyPI Trusted Publishing (B1–B4) **before** tagging.
4. Reserve/verify the PyPI name and the GHCR package name.
5. Tag `v0.3.0` (A6) → approve the release run → confirm `pip install` and
   `docker pull` both work from a clean machine.
6. Only then announce (see `docs/show-hn.md`).

A Show HN whose `pip install` fails in the first comment is hard to recover from
— prove the install works before you post.
