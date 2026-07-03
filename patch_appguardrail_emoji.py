import re

with open("scanner/cli/appguardrail.py", "r") as f:
    content = f.read()

emojis = [
    "✅", "✨", "🚀", "💡", "⚙️", "❌", "🧭", "🧩", "🔎", "🐍",
    "🌐", "🧾", "🔴", "🔵", "🟠", "🟡", "⏭️", "🔍", "⚠️", "⚡",
    "⚙", "⚠"
]

patch_template = """
def strip_emoji(text):
    if not bool(os.getenv("APPGUARDRAIL_NO_EMOJI")):
        return text
    for e in {emojis}:
        text = text.replace(e + "  ", "")
        text = text.replace(e + " ", "")
        text = text.replace(e, "")
    return text
"""
patch = patch_template.format(emojis=str(emojis))

# Inject after imports
content = content.replace("from pathlib import Path", "from pathlib import Path\nimport os\n" + patch)

# Find all print statements with strings containing emojis
# and wrap the string argument with strip_emoji()
def replacer(match):
    # This is a complex regex task, might be easier to just conditionally replace print globally inside the file using string manipulation
    pass

with open("scanner/cli/appguardrail.py", "w") as f:
    f.write(content)
