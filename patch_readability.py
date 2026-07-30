import re
from pathlib import Path

# Fix language.py readability
content = Path("appguardrail_core/language.py").read_text()
content = content.replace("chr(92)", "r'\\\\'") # Using raw string or just escaping '\\\\'
Path("appguardrail_core/language.py").write_text(content)
