"""Run the full suite and write reports to ./reports.

    python run_tests.py            # everything (live Ollama test auto-skips if not running)
    python run_tests.py -m "not integration"
"""

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
REPORTS = HERE / "reports"

if __name__ == "__main__":
    REPORTS.mkdir(exist_ok=True)
    sys.exit(pytest.main([
        "-v",
        f"--html={REPORTS / 'test-report.html'}", "--self-contained-html",
        f"--junitxml={REPORTS / 'junit.xml'}",
        "--cov=sentinel", "--cov-report=term-missing",
        f"--cov-report=html:{REPORTS / 'coverage'}",
        f"--cov-report=json:{REPORTS / 'coverage.json'}",
        *sys.argv[1:],
    ]))
