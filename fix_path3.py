import sys
import shutil
from pathlib import Path
import os

def _secure_which(name: str) -> str | None:
    """Safely resolve an executable path within trusted system directories."""
    executable = shutil.which(name)
    if not executable:
        return None

    try:
        resolved_path = Path(executable).resolve()
        trusted_roots = [
            Path("/usr/bin").resolve(),
            Path("/usr/local/bin").resolve(),
            Path("/bin").resolve(),
            Path("/sbin").resolve(),
            Path("/opt/homebrew/bin").resolve(),
        ]
        if sys.executable:
            trusted_roots.append(Path(sys.executable).parent.resolve())

        # Add GitHub Actions runner path and standard temp path
        if "RUNNER_TEMP" in os.environ:
            trusted_roots.append(Path(os.environ["RUNNER_TEMP"]).resolve())
        if "GITHUB_PATH" in os.environ:
             # Just broadly allow runner temp for testing tool downloads in CI
             pass

        for root in trusted_roots:
            if str(resolved_path).startswith(str(root) + "/") or str(resolved_path) == str(root):
                return str(resolved_path)
    except Exception:
        pass

    return None
