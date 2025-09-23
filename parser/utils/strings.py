import re

def hex_to_text(s: str) -> str:
    if not s:
        return s
    h = s[2:] if s.lower().startswith("0x") else s
    if not re.fullmatch(r"[0-9a-fA-F]+", h) or len(h) % 2 != 0:
        return s
    try:
        t = bytes.fromhex(h).decode("utf-8", "replace")
        return t.replace("\x00", " ").strip()
    except Exception:
        return s

def kv_to_dict(s: str) -> dict:
    d = {}
    for tok in s.split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            d[k] = v
    return d