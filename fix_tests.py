import re

file_path = "tests/test_coverage_edge_cases.py"
with open(file_path, "r") as f:
    content = f.read()

content = content.replace('patch("shutil.which", return_value="trivy")', 'patch("scanner.cli.appguardrail._secure_which", return_value="trivy")')
content = content.replace('patch("shutil.which", return_value="codegraph")', 'patch("scanner.cli.appguardrail._secure_which", return_value="codegraph")')

with open(file_path, "w") as f:
    f.write(content)
