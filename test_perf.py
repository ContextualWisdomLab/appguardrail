import cProfile
import pstats
from scanner.cli.appguardrail import cmd_scan

class DummyArgs:
    path = "test_files"
    trivy = False
    external = "off"
    bandit = False
    ruff = False
    semgrep = False
    zap_baseline = None
    findings_json = None
    codegraph = False
    sarif = None
    push = None

import os
os.makedirs("test_files", exist_ok=True)
for i in range(100):
    with open(f"test_files/file_{i}.py", "w") as f:
        f.write("content\n" * 10)

args = DummyArgs()

profiler = cProfile.Profile()
profiler.enable()
for _ in range(10):
    cmd_scan(args)
profiler.disable()
stats = pstats.Stats(profiler).sort_stats('cumtime')
stats.print_stats(30)
