import re
from pathlib import Path

content = Path("appguardrail_core/language.py").read_text()

# Replace chr(92) with '\\\\'
content = content.replace("chr(92)", "'\\\\\\\\'")

# Add comments for optimization in language.py
content = content.replace(
    """        else:
            slash_idx = file_path.rfind("/")""",
    """        else:
            # ⚡ Bolt: Fast path extraction using string operations instead of os.path.basename
            # and os.path.splitext to avoid object allocation and stat overhead in hot loops.
            slash_idx = file_path.rfind("/")"""
)

Path("appguardrail_core/language.py").write_text(content)

appguardrail_content = Path("scanner/cli/appguardrail.py").read_text()
appguardrail_content = appguardrail_content.replace(
    """                        elif entry.is_file(follow_symlinks=False):
                            ext_idx = entry.name.rfind(".")""",
    """                        elif entry.is_file(follow_symlinks=False):
                            # ⚡ Bolt: Fast file extension extraction via rfind to avoid
                            # os.path.splitext overhead during massive directory traversal.
                            ext_idx = entry.name.rfind(".")"""
)
Path("scanner/cli/appguardrail.py").write_text(appguardrail_content)
