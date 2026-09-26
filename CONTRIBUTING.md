# Contributing to Sandbox Sentinel

Thanks for helping make AI agents safer! Contributions of all sizes are welcome — a new detection rule, a bug fix, docs, or an example prompt.

## Quick start

```bash
git clone https://github.com/Lalithprabu/sandbox-sentinel.git
cd sandbox-sentinel
pip install -r requirements.txt
python run_tests.py          # 104 tests + coverage into reports/
streamlit run app.py         # the demo at http://localhost:8501
```

## The one rule for contributions: **add a test**

Every behaviour change needs a test, and the suite must stay green.

```bash
python -m pytest -q                    # everything (uses local Ollama if present)
python -m pytest -q -m "not integration"   # what CI runs; no Ollama needed
```

## Adding a detection rule (the most useful contribution)

1. Add a `Rule(...)` to `RULES` in [`sentinel/rules.py`](sentinel/rules.py). Keep the regex readable and the severity honest (`low`/`medium`/`high`/`critical`).
2. Add a safer-alternative line for its id in `SAFER` in [`sentinel/advice.py`](sentinel/advice.py) — a test enforces that **every rule has one**.
3. Add at least one positive and one negative test in `tests/`.
4. If it belongs in the story, add an example to [`sentinel/prompts.py`](sentinel/prompts.py) or `scenarios.py`.

Keep false positives in mind: a rule that fires on everyday commands (`git`, `pytest`, `pip`) will get turned off. When in doubt, choose a lower severity so it routes to **review** rather than **block**.

## Style

- Match the surrounding code. Type hints, small functions, clear names.
- No new runtime dependencies without discussion — staying dependency-light is a feature.
- Keep it framework-agnostic: the core (`sentinel/`) must not import Streamlit.

## Pull requests

- Branch from `main`, keep the PR focused, and describe the behaviour change.
- CI runs the suite on Python 3.10–3.12; it must pass.
- By contributing you agree your work is licensed under the repo's [MIT License](LICENSE).

Questions? Open a [discussion or issue](https://github.com/Lalithprabu/sandbox-sentinel/issues), or reach out to [LalithPrabu](https://github.com/Lalithprabu).
