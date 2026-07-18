with open("appguardrail_core/controlplane.py", "r") as f:
    content = f.read()

search = """from importlib import \\
    resources  # nosemgrep: python.lang.compatibility.python37.python37-compatibility-importlib2"""

replace = """import importlib.resources  # nosemgrep: python.lang.compatibility.python37.python37-compatibility-importlib2"""

if search in content:
    with open("appguardrail_core/controlplane.py", "w") as f:
        f.write(content.replace(search, replace))
    print("Patched appguardrail_core/controlplane.py successfully.")
else:
    print("Search block not found in appguardrail_core/controlplane.py")
