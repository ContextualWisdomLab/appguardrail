import re
regex = r'\b(?P<webhook_url_var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^\)\n]*\)|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)(?:\.get\s*\(\s*["\x27]url["\x27]\s*\)|\[\s*["\x27]url["\x27]\s*\])'
print(bool(re.search(regex, 'webhook_url = body.get("url", None)')))
print(bool(re.search(regex, 'webhook_url = body.get("url")')))
