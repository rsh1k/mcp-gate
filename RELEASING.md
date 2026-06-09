# Releasing mcp-gate

This is the checklist for cutting a release to **PyPI** (the Python package
index) and **GHCR** (GitHub Container Registry). It assumes you are the
maintainer with publish rights.

---

## 0. Pre-flight (every release)

```bash
# Clean tree, tests green
python tests/test_core.py        # 37 unit tests must pass
python tests/test_samples.py     # 20/20 samples must pass
python -m mcpgate.cli check --policy examples/policy.yaml
```

- [ ] Bump the version in **`pyproject.toml`** and **`mcpgate/__init__.py`**
      (keep them identical).
- [ ] Update **`CHANGELOG.md`** with the new version and date.
- [ ] Commit: `git commit -am "release: vX.Y.Z"`.

Versioning: pre-1.0, a minor bump (`0.2 → 0.3`) may include breaking changes;
patch bumps (`0.2.0 → 0.2.1`) are fixes only. After 1.0, follow semver strictly.

---

## 1. Build the distribution

```bash
pip install --upgrade build twine
rm -rf dist/ build/ *.egg-info
python -m build            # produces dist/*.whl and dist/*.tar.gz
twine check dist/*         # validates metadata renders on PyPI
```

`twine check` must report `PASSED` for both files before you upload.

---

## 2. Test on TestPyPI first (recommended for the first release)

TestPyPI is a separate sandbox index so you can rehearse without burning a real
version number.

```bash
twine upload --repository testpypi dist/*
# then, in a throwaway venv:
python -m venv /tmp/t && . /tmp/t/bin/activate
pip install --index-url https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ mcp-gate
mcp-gate --help
deactivate
```

The `--extra-index-url` is needed so dependencies resolve from real PyPI.

---

## 3. Publish to PyPI

**Use a scoped API token, never your password.** Create one at
<https://pypi.org/manage/account/token/> (scope it to the `mcp-gate` project
after the first upload). Store it as `~/.pypirc` or an env var; do not commit it.

```bash
twine upload dist/*
# username: __token__
# password: pypi-<your-token>
```

Verify:

```bash
pip install mcp-gate          # from a clean environment
mcp-gate controls
```

### First-upload note
The project name `mcp-gate` must be available on PyPI. Check
<https://pypi.org/project/mcp-gate/> first; if taken, pick a distinct name and
update `pyproject.toml` (`[project].name`) and the README install instructions.

---

## 4. Tag the release on GitHub

```bash
git tag -a vX.Y.Z -m "mcp-gate vX.Y.Z"
git push origin main --tags
```

Then create a GitHub Release from the tag and paste the relevant
`CHANGELOG.md` section as the notes.

---

## 5. Publish the container image to GHCR

```bash
# One-time: a classic PAT with write:packages scope, or use GITHUB_TOKEN in CI.
echo "$GHCR_TOKEN" | docker login ghcr.io -u rsh1k --password-stdin

docker build -t ghcr.io/rsh1k/mcp-gate:vX.Y.Z \
             -t ghcr.io/rsh1k/mcp-gate:latest .
docker push ghcr.io/rsh1k/mcp-gate:vX.Y.Z
docker push ghcr.io/rsh1k/mcp-gate:latest
```

Make the package public in the repo's Packages settings if you want anonymous
`docker pull`.

---

## 6. Automate it (optional but recommended)

Add a release workflow that triggers on a version tag and publishes to PyPI via
**Trusted Publishing** (OIDC, no stored token). Outline:

```yaml
# .github/workflows/release.yml
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
  id-token: write        # required for PyPI Trusted Publishing
  packages: write        # required for GHCR
jobs:
  pypi:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.12"}
      - run: pip install build && python -m build
      - uses: pypa/gh-action-pypi-publish@release/v1   # uses OIDC, no token
  image:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:latest,ghcr.io/${{ github.repository }}:${{ github.ref_name }}
```

Set up Trusted Publishing once at
<https://pypi.org/manage/project/mcp-gate/settings/publishing/> so the workflow
needs no stored PyPI token.

---

## Post-release

- [ ] Confirm `pip install mcp-gate` works from a clean machine.
- [ ] Confirm `docker pull ghcr.io/rsh1k/mcp-gate:latest` works.
- [ ] Announce (see `docs/show-hn.md`).
- [ ] Open a milestone for the next version.
