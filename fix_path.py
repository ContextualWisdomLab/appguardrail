def _secure_which(name: str) -> str | None:
    """Safely resolve an executable path within trusted system directories."""
    import os
    import shutil
    from pathlib import Path

    # Allowed trusted root paths for system executables
    trusted_roots = ("/usr/bin", "/usr/local/bin", "/bin", "/sbin", "/opt/homebrew/bin")
    executable = shutil.which(name)
    if not executable:
        return None

    try:
        resolved_path = Path(executable).resolve()
        for root in trusted_roots:
            if str(resolved_path).startswith(root + "/") or str(resolved_path) == root:
                return str(resolved_path)
    except Exception:
        pass

    return None
