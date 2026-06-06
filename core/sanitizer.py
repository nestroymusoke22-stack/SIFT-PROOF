INJECTION_CHARS = [';', '&&', '||', '|', '`', '$(', ')']
DESTRUCTIVE_KEYWORDS = [
    'rm ', 'rm\t', 'del ', 'format ', 'mkfs', 'shred',
    'wipe', '> /dev/', 'DROP TABLE', 'DELETE FROM',
    'TRUNCATE', '--no-preserve', 'zero'
]


def sanitize_args(args):
    """
    Validates subprocess argument list before execution.
    Returns (True, None) if safe.
    Returns (False, reason_string) if unsafe.
    """
    if not isinstance(args, (list, tuple)):
        return False, f"Args must be a list, got: {type(args).__name__}"

    for arg in args:
        s = str(arg)
        for ch in INJECTION_CHARS:
            if ch in s:
                return False, (
                    f"SECURITY_BLOCK: Injection char '{ch}' in arg: {s[:60]}"
                )
        for kw in DESTRUCTIVE_KEYWORDS:
            if kw.lower() in s.lower():
                return False, (
                    f"SECURITY_BLOCK: Destructive keyword '{kw.strip()}' in arg: {s[:60]}"
                )
    return True, None


def safe_run(args, **kwargs):
    """
    Drop-in replacement for subprocess.run() with sanitization gate.
    Raises ValueError with safe error message if injection detected.
    The LLM receives the error message and must adapt.
    """
    import subprocess
    safe, reason = sanitize_args(args)
    if not safe:
        raise ValueError(f"SANITIZER_BLOCKED — {reason}")
    return subprocess.run(args, **kwargs)