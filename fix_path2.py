def _secure_which(name: str) -> str | None:
    """Safely resolve an executable path within trusted system directories."""
    executable = shutil.which(name)
    if not executable:
        return None

    try:
        resolved_path = Path(executable).resolve()
        trusted_roots = (
            Path("/usr/bin").resolve(),
            Path("/usr/local/bin").resolve(),
            Path("/bin").resolve(),
            Path("/sbin").resolve(),
            Path("/opt/homebrew/bin").resolve(),
            Path(sys.executable).parent.resolve() if sys.executable else Path("/opt/homebrew/bin")
        )
        for root in trusted_roots:
            if str(resolved_path).startswith(str(root) + "/") or str(resolved_path) == str(root):
                return str(resolved_path)
    except Exception:
        pass

    return None
