import re

with open("scanner/cli/appguardrail.py", "r") as f:
    content = f.read()

# Replace pluralizations:
# files_word
# critical_word
# high_word
# warnings_word
# info_word
# finding_word
# issue_word
# these_word

patch_plurals = """
    files_word = "file" if files_scanned == 1 else "files"
    critical_word = "critical issue" if counts["CRITICAL"] == 1 else "critical issues"
    high_word = "high issue" if counts["HIGH"] == 1 else "high issues"
    warnings_word = "warning" if counts["WARNING"] == 1 else "warnings"
    info_word = "info issue" if counts["INFO"] == 1 else "info issues"
"""

def plural(count, sing, plur=None):
    return sing if count == 1 else (plur or sing + "s")
