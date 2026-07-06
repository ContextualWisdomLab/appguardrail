with open("scanner/cli/appguardrail.py", "r") as f:
    code = f.read()

code = code.replace("    import re\n", "")
code = code.replace("    import os\n", "")

with open("scanner/cli/appguardrail.py", "w") as f:
    f.write(code)
