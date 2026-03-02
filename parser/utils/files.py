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


def is_compressed(file_path: Path) -> bool:
    name = file_path.name
    return name.endswith(".tar.gz") or name.endswith(".tgz") or name.endswith(".gz")


def decompress(file_path: Path, dest_dir: Path) -> list[Path]:
    """
    압축 파일을 dest_dir 에 해제하고 생성된 파일 목록을 반환.

    지원 형식:
      - .tar.gz / .tgz  → tarfile 로 전체 해제
      - .gz             → gzip 단일 파일 해제 (확장자 .gz 제거)
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = file_path.name
    extracted: list[Path] = []

    if name.endswith(".tar.gz") or name.endswith(".tgz"):
        with tarfile.open(file_path, "r:gz") as tar:
            tar.extractall(path=dest_dir)
            extracted = [dest_dir / m.name for m in tar.getmembers() if m.isfile()]

    elif name.endswith(".gz"):
        out_name = name[:-3]  # 확장자 .gz 제거
        out_path = dest_dir / out_name
        with gzip.open(file_path, "rb") as gz_in:
            with open(out_path, "wb") as f_out:
                shutil.copyfileobj(gz_in, f_out)
        extracted = [out_path]

    return extracted