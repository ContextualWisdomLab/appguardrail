import time
import os

SKIP_EXTENSIONS = {
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".webm", ".pdf", ".zip", ".tar",
    ".gz", ".bz2", ".xz", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".class",
    ".jar", ".war", ".ear", ".map", ".log"
}

def orig(entry_name):
    idx = entry_name.rfind(".")
    ext = (
        entry_name[idx:]
        if idx > 0 and entry_name[:idx].replace(".", "")
        else ""
    )
    return ext.lower() not in SKIP_EXTENSIONS

def fast(entry_name):
    # This is slightly faster because it avoids string copies on files without dots
    # But does it warrant a PR? Probably not big enough
    pass
