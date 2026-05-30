import argparse
import os
import sys
from pathlib import Path

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

def scan(args):
    path = args.path
    print(f"Scanning directory: {path}")

    dangerous_patterns = {
        "SUPABASE_SERVICE_ROLE_KEY": "Hardcoded Supabase Service Role Key found",
        "STRIPE_SECRET_KEY": "Hardcoded Stripe Secret Key found",
        "origin: \"*\"": "Dangerous CORS setting (origin: '*') found",
        "allow read, write: if true": "Public Firebase rules found",
    }

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
                    for pattern, warning in dangerous_patterns.items():
                        if pattern in content:
                            findings.append(f"{file_path}: {warning}")
            except Exception:
                pass

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
