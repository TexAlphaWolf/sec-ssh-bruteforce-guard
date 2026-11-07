# Contributing

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest --cov
sudo "$(which python)" -m pytest -m nft           # the real-firewall tests (Linux, root)
```

- Standard library only for the package. A new runtime dependency needs a very good reason.
- A new log pattern needs a test with the real sshd line **and** a test that a hostile user name cannot move the blame to another address.
- Anything that reaches `nft` or a subprocess takes an address through `net.normalize_target` first.
- If you change a default, rerun `tools/evaluate.py` and update the table in the README.
