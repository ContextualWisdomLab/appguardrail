from mcp.server.fastmcp import FastMCP
import subprocess
import os
import json

mcp = FastMCP("vibesec")

@mcp.tool()
def scan(path: str = ".") -> str:
    """Run a lightweight security scan using VibeSec."""
    try:
        # We need to run vibesec via python to ensure we use the local package
        # Assuming the root directory has scanner/cli/vibesec.py
        result = subprocess.run(
            ["python", "scanner/cli/vibesec.py", "scan", path],
            capture_output=True,
            text=True,
            check=False
        )
        return result.stdout + result.stderr
    except Exception as e:
        return f"Error running scan: {e}"

@mcp.tool()
def review(stack: str = None, db: str = None, payments: str = None) -> str:
    """Generate an AI security review prompt."""
    try:
        cmd = ["python", "scanner/cli/vibesec.py", "review"]
        if stack:
            cmd.extend(["--stack", stack])
        if db:
            cmd.extend(["--db", db])
        if payments:
            cmd.extend(["--payments", payments])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False
        )
        return result.stdout + result.stderr
    except Exception as e:
        return f"Error running review: {e}"

if __name__ == "__main__":
    mcp.run(transport='stdio')
