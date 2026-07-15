import subprocess
print(subprocess.run(["uv", "run", "--with", "coverage", "--with", "pytest", "coverage", "run", "-m", "pytest", "tests"], capture_output=True, text=True).stderr)
