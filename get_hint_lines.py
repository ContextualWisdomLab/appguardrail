with open("scanner/cli/appguardrail.py", "r") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "💡 Hint:" in line:
        print(f"{i+1}: {line.strip()}")
