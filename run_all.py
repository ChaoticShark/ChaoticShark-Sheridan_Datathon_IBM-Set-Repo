"""
One command to reproduce everything:
    python run_all.py              # backtest -> score 2026 -> Granite -> verify
    python run_all.py --no-granite # skip the Granite step (e.g. no Ollama available)
"""
import subprocess
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
steps = [
    ("Walk-forward backtest", ["pipeline/backtest.py"]),
    ("Robustness checks", ["pipeline/robustness.py"]),
    ("Score 2026 scoreboard -> top500.csv", ["pipeline/score_2026.py"]),
]
if "--no-granite" not in sys.argv:
    steps.append(("Granite explanations (grounded + validated)", ["pipeline/granite_layer.py", "--n", "500"]))
steps.append(("Dashboard", ["pipeline/build_dashboard.py"]))
steps.append(("Integrity checks", ["pipeline/verify.py"]))

for name, cmd in steps:
    print(f"\n=== {name} ===", flush=True)
    r = subprocess.run([sys.executable] + [os.path.join(HERE, cmd[0])] + cmd[1:], cwd=HERE)
    if r.returncode != 0:
        sys.exit(f"step failed: {name}")
print("\nAll steps finished.")
