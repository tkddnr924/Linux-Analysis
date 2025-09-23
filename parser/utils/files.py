from pathlib import Path

def count_glob(dir_path: Path, pattern: str) -> int:
    return sum(1 for p in dir_path.glob(pattern) if p.is_file())