import argparse
import os
import sys
from pathlib import Path

# Try importing yaml for parsing the rules.
# We'll fail gracefully if it's not installed in the current env during direct script execution.
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

def init(args):
    tool = args.tool
    stack = args.stack

    print(f"Initializing VibeSec...")

    if tool == 'cursor':
        os.makedirs('.cursor/rules', exist_ok=True)
        with open('.cursor/rules/vibesec.md', 'w') as f:
            f.write("# VibeSec Cursor Rules\n\nAlways enforce authentication and ownership checks.\nNever expose service role keys to client-side code.\n")
        print("Created .cursor/rules/vibesec.md")
    elif tool == 'claude-code':
        with open('CLAUDE.md', 'a') as f:
            f.write("\n# VibeSec Security Guidelines\n\nAlways enforce authentication and ownership checks.\nNever expose service role keys to client-side code.\n")
        print("Updated CLAUDE.md")

    if stack:
        with open('VIBESEC_CHECKLIST.md', 'w') as f:
            f.write(f"# Security Checklist for {stack}\n\n- [ ] Ensure API routes are authenticated.\n- [ ] Check Row Level Security (RLS) rules.\n")
        print("Created VIBESEC_CHECKLIST.md")

    print("Initialization complete.")

def load_rules():
    if not HAS_YAML:
        print("[!] PyYAML is not installed. Using default fallback rules.")
        print("[!] Please install the package using 'pip install .' to use external YML rules.")
        return [
            {"pattern": "SUPABASE_SERVICE_ROLE_KEY", "message": "Hardcoded Supabase Service Role Key found", "severity": "CRITICAL"},
            {"pattern": "STRIPE_SECRET_KEY", "message": "Hardcoded Stripe Secret Key found", "severity": "CRITICAL"},
            {"pattern": "origin: \"*\"", "message": "Dangerous CORS setting (origin: '*') found", "severity": "HIGH"},
            {"pattern": "allow read, write: if true", "message": "Public Firebase rules found", "severity": "CRITICAL"}
        ]

    rules_dir = Path(__file__).resolve().parent.parent / "rules"
    combined_rules = []

    if rules_dir.exists() and rules_dir.is_dir():
        for rule_file in rules_dir.glob("*.yml"):
            try:
                with open(rule_file, "r") as f:
                    data = yaml.safe_load(f)
                    if data and "rules" in data:
                        combined_rules.extend(data["rules"])
            except Exception as e:
                print(f"Warning: Failed to parse rule file {rule_file}: {e}")

    return combined_rules

def extract_patterns(rule):
    patterns = []
    # Handle single pattern
    if "pattern" in rule:
        patterns.append(rule["pattern"])

    # Handle semgrep-style patterns list
    if "patterns" in rule and isinstance(rule["patterns"], list):
        for p in rule["patterns"]:
            if isinstance(p, str):
                patterns.append(p)
            elif isinstance(p, dict):
                # E.g. {"pattern": "...", "pattern-regex": "..."}
                if "pattern" in p:
                    patterns.append(p["pattern"])
                # We skip pattern-regex for now as we're doing simple string matching in MVP
    return patterns

def scan(args):
    path = args.path
    print(f"Scanning directory: {path}")

    rules = load_rules()
    if not rules:
        print("No rules loaded. Exiting.")
        return

    findings = []

    for root, dirs, files in os.walk(path):
        if '.git' in dirs:
            dirs.remove('.git')
        for file in files:
            file_path = os.path.join(root, file)
            # Skip binary and very large files
            if not file_path.endswith(('.py', '.js', '.ts', '.jsx', '.tsx', '.json', '.yml', '.yaml', '.md', '.env')):
                continue

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except (UnicodeDecodeError, IOError):
                # Only ignore file read/decoding errors
                continue

            for rule in rules:
                patterns_to_check = extract_patterns(rule)

                for p in patterns_to_check:
                    # In a real scanner this would be robust regex or AST parsing.
                    # For this MVP, we do simple string subset matching.
                    # Be careful with multi-line patterns.
                    # If it's a simple string, we just check if it's in content.
                    if p.strip() and p.strip() in content:
                        findings.append(f"{file_path} [{rule.get('severity', 'UNKNOWN')}]: {rule['message'].strip()}")
                        break # Prevent duplicate findings for the same rule in a single file

    if findings:
        print("\n[!] Vulnerabilities found:")
        for finding in findings:
            print(f"  - {finding}")
        sys.exit(1)
    else:
        print("\n[+] No obvious vulnerabilities found. Good job!")

def review(args):
    stack = args.stack
    db = args.db
    payments = args.payments

    prompt = f"""Copy this prompt into Claude Code / Cursor:
Review this codebase for:
1. Missing server-side authorization checks for {stack}
2. {db.capitalize()} RLS bypass risks
3. Exposed secrets
"""
    if payments:
        prompt += f"4. {payments.capitalize()} webhook verification issues\n"

    prompt += "5. Admin route access control"

    print(prompt)

def main():
    parser = argparse.ArgumentParser(description="VibeSec: Security guardrails for vibe-coded apps.")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Init command
    parser_init = subparsers.add_parser('init', help='Initialize security rules in your project')
    parser_init.add_argument('--tool', choices=['cursor', 'claude-code', 'windsurf', 'lovable'], help='The AI coding tool you are using')
    parser_init.add_argument('--stack', help='The tech stack (e.g., nextjs-supabase)')

    # Scan command
    parser_scan = subparsers.add_parser('scan', help='Run a lightweight security scan')
    parser_scan.add_argument('path', nargs='?', default='.', help='Directory to scan')

    # Review command
    parser_review = subparsers.add_parser('review', help='Generate a security review prompt')
    parser_review.add_argument('--stack', default='your stack', help='Tech stack')
    parser_review.add_argument('--db', default='database', help='Database used')
    parser_review.add_argument('--payments', help='Payment provider used')

    args = parser.parse_args()

    if args.command == 'init':
        init(args)
    elif args.command == 'scan':
        scan(args)
    elif args.command == 'review':
        review(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
