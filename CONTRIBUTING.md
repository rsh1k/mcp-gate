# Contributing to mcp-gate

Thanks for your interest. This project values correctness and clarity over
feature count — it is security-critical software.

## Ground rules

1. **Every behavior change needs a test.** The test corpus is how we keep the
   false-positive/false-negative rate honest. Add cases to `tests/test_core.py`
   (unit) or `tests/test_samples.py` (labeled end-to-end samples).
2. **No new runtime dependencies in the core** without discussion. The core is
   stdlib-only on purpose; that is part of what makes it auditable and easy to
   self-host. Optional features can live behind extras (e.g. `[yaml]`).
3. **No `eval`, `exec`, or dynamic code execution** in the policy/condition
   path, ever. The whole point is that policy authors cannot run code.
4. **Mark unfinished hardening** with a `# HARDENING:` comment so it is greppable
   and shows up honestly to users.
5. **Keep the engine pure.** I/O, networking, and transport belong in the proxy
   and enforcement layers, not in `engine.py`.

## Development setup

```bash
pip install -e ".[dev]"
python tests/test_core.py
python tests/test_samples.py
```

## Pull requests

- Keep PRs focused. One concern per PR.
- Update the README and the control mapping (`compliance.py`) if you change what
  the tool does or which frameworks it maps to.
- Be explicit in the PR description about security implications.

## Good first contributions

- Additional threat-scanner patterns (with tests and a clear category).
- New condition operators (with tests).
- HTTP/streamable transport support (see roadmap item 1).
- A durable `SessionStore` backend (see roadmap item 2).
