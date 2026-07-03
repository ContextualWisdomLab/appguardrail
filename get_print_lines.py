import re

with open("scanner/cli/appguardrail.py", "r") as f:
    content = f.read()

emojis = [
    "✅", "✨", "🚀", "💡", "⚙️", "❌", "🧭", "🧩", "🔎", "🐍",
    "🌐", "🧾", "🔴", "🔵", "🟠", "🟡", "⏭️", "🔍", "⚠️", "⚡",
    "⚙", "⚠", "─", "═"
]

lines = content.split('\n')
for i, line in enumerate(lines):
    if "print(" in line:
        has_emoji = any(e in line for e in emojis)
        if has_emoji:
            print(f"{i+1}: {line.strip()}")
