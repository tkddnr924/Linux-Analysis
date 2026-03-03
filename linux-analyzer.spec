# -*- mode: python ; coding: utf-8 -*-
"""
linux-analyzer.spec — PyInstaller 빌드 설정

빌드 명령:
  # 가상환경 활성화 후
  pip install pyinstaller
  pyinstaller linux-analyzer.spec

출력:
  dist/linux-analyzer          (macOS/Linux 단일 바이너리)
  dist/linux-analyzer.exe      (Windows 단일 실행파일)
"""

from PyInstaller.utils.hooks import collect_submodules

# analyzer/ 는 __init__.py 있음 → collect_submodules 사용
# parser/   는 __init__.py 없는 namespace package → 직접 열거
hidden_imports = collect_submodules('analyzer') + [
    'parser.auditlog',
    'parser.authlog',
    'parser.nginxlog',
    'parser.utils.files',
    'parser.utils.strings',
    'parser.utils.times',
]

a = Analysis(
    ['main.py'],
    pathex=['.'],           # 프로젝트 루트를 탐색 경로에 포함
    binaries=[],
    datas=[],               # target/, *.db 는 런타임에 생성되므로 미포함
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # 불필요한 대형 모듈 제외 → 바이너리 크기 최소화
    excludes=[
        'tkinter', 'matplotlib', 'numpy', 'pandas',
        'PIL', 'PyQt5', 'PyQt6', 'wx',
        'IPython', 'notebook', 'scipy',
    ],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='linux-analyzer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,               # UPX 압축 (설치 시 크기 감소, 선택사항)
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,           # CLI 도구 → 콘솔 창 유지
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
