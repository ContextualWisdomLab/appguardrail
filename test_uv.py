import subprocess
print(subprocess.run(["uv", "sync", "--project", ".", "--no-build", "--no-install-project"], capture_output=True, text=True).stderr)
