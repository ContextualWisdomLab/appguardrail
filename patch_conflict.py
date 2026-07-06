with open("scanner/cli/appguardrail.py", "r") as f:
    text = f.read()

import re
resolved = re.sub(
    r'<<<<<<< HEAD\n.*?=======\n(.*?)\n>>>>>>> origin/develop',
    r'\1',
    text,
    flags=re.DOTALL
)

with open("scanner/cli/appguardrail.py", "w") as f:
    f.write(resolved)
