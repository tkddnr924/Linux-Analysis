import gzip
import hashlib
import shutil
import tarfile
from pathlib import Path


def count_glob(dir_path: Path, pattern: str) -> int:
    return sum(1 for p in dir_path.glob(pattern) if p.is_file())


def md5(file_path: Path, chunk_size: int = 8192) -> str:
    h = hashlib.md5()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def _is_gzip_magic(file_path: Path) -> bool:
    """gzip 시그니처 1f 8b 인지(확장자 무관 판별용)."""
    try:
        with open(file_path, "rb") as f:
            return f.read(2) == b'\x1f\x8b'
    except Exception:
        return False


def _is_tar_file(file_path: Path) -> bool:
    """POSIX tar 의 ustar 매직(257 바이트 오프셋)으로 판별."""
    try:
        with open(file_path, "rb") as f:
            f.seek(257)
            return f.read(5) == b'ustar'
    except Exception:
        return False


def is_compressed(file_path: Path) -> bool:
    """
    확장자 또는 매직바이트로 압축 여부 판별.
    `.gz`/`.tgz`/`.tar.gz` 가 아니어도 파일 헤더가 1f 8b 면 gzip 으로 간주
    (예: nginx 가 access.log 자리에 .gz 를 그대로 쓰는 경우).
    """
    name = file_path.name
    if name.endswith(".tar.gz") or name.endswith(".tgz") or name.endswith(".gz"):
        return True
    return _is_gzip_magic(file_path)


def decompress(file_path: Path, dest_dir: Path) -> list[Path]:
    """
    압축 파일을 dest_dir 에 해제하고 생성된 파일 목록을 반환.

    지원 형식:
      - .tar.gz / .tgz                          → tarfile 로 전체 해제
      - .gz (또는 매직바이트만 gzip)             → gzip 해제. 결과가 tar 아카이브면(ustar)
                                                    이어서 tar 까지 해제(.tar.gz 의 확장자 없는 변형 대응).
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = file_path.name
    extracted: list[Path] = []

    # 1) 명시적 tar.gz/tgz
    if name.endswith(".tar.gz") or name.endswith(".tgz"):
        with tarfile.open(file_path, "r:gz") as tar:
            tar.extractall(path=dest_dir)
        return [dest_dir / m.name for m in tar.getmembers() if m.isfile()]

    # 2) .gz 또는 확장자 없는 gzip
    if name.endswith(".gz") or _is_gzip_magic(file_path):
        out_name = name[:-3] if name.endswith(".gz") else (name + ".decomp")
        out_path = dest_dir / out_name
        with gzip.open(file_path, "rb") as gz_in, open(out_path, "wb") as f_out:
            shutil.copyfileobj(gz_in, f_out)

        # gzip 해제 결과가 tar 아카이브면 한 번 더 해제 (확장자 없는 tar.gz 대응)
        if _is_tar_file(out_path):
            with tarfile.open(out_path, "r") as tar:
                tar.extractall(path=dest_dir)
                extracted = [dest_dir / m.name for m in tar.getmembers() if m.isfile()]
            try: out_path.unlink()
            except Exception: pass
            return extracted

        return [out_path]

    return []