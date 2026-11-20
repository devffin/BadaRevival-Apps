#!/usr/bin/env python3
"""
gce2elf.core — GCE compressed .so decompression core logic

Based on original gce2elf.trx v0.32 by b.kubica, rewritten with Python + Unicorn Engine by AI.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

try:
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE
    from unicorn.arm_const import (
        UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP, UC_ARM_REG_LR,
    )
    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False
    # Type stubs
    Uc = None  # type: ignore
    UC_ARCH_ARM = 0  # type: ignore
    UC_MODE_ARM = 0  # type: ignore
    UC_MODE_LITTLE_ENDIAN = 0  # type: ignore
    UC_HOOK_CODE = 1  # type: ignore
    UC_ARM_REG_R0 = 0  # type: ignore
    UC_ARM_REG_R1 = 0  # type: ignore
    UC_ARM_REG_SP = 0  # type: ignore
    UC_ARM_REG_LR = 0  # type: ignore

__version__ = "0.0.1"

# ── Constants ─────────────────────────────────────────

DRAM_BASE   = 0x40000000
DRAM_SIZE   = 0x01000000   # 16 MB
QMD_BASE    = 0xF0000000
QMD_SIZE    = 0x00100000   # 1 MB
STACK_BASE  = 0xFEF00000
STACK_SIZE  = 0x00100000   # 1 MB
FILE_BASE   = 0x00000000
FILE_SIZE   = 0x00200000   # 2 MB (src_addr = FILE_BASE + 0x100000)

RETURN_ADDR = 0xF0000008   # Decompression completion breakpoint
STACK_PTR   = 0xFF000000   # Initial SP

ENGINE_FILES: dict[int, str] = {
    0xB4: "engine_b4.bin",
    0xAD: "engine_ad.bin",
    0x97: "engine_97.bin",
}

# Package-internal engine directory
_ENGINE_PKG_DIR = Path(__file__).parent / "engines"


# ── Internal Functions ────────────────────────────────

def _load_engine(qram3: int, engine_dir: str | Path | None = None) -> bytes | None:
    """Load the engine binary for the given QRAM version"""
    filename = ENGINE_FILES.get(qram3)
    if not filename:
        return None

    # Search priority: specified dir > package engines/ > package parent > cwd
    search_dirs = []
    if engine_dir:
        search_dirs.append(Path(engine_dir))
    search_dirs.append(_ENGINE_PKG_DIR)                     # package engines/
    search_dirs.append(Path(__file__).parent.parent)        # package parent
    search_dirs.append(Path.cwd())                          # current working dir

    for d in search_dirs:
        path = d / filename
        if path.exists():
            return path.read_bytes()

    return None


def _decompress_arm(dst: int, src_data: bytes, engine: bytes) -> bytes | None:
    """Decompress a single data chunk via ARM emulation"""
    if not HAS_UNICORN:
        raise RuntimeError("Unicorn not installed: pip install unicorn")

    assert Uc is not None
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)

    mu.mem_map(FILE_BASE,  FILE_SIZE)
    mu.mem_map(DRAM_BASE,  DRAM_SIZE)
    mu.mem_map(QMD_BASE,   QMD_SIZE)
    mu.mem_map(STACK_BASE, STACK_SIZE)

    mu.mem_write(QMD_BASE, engine)

    src_addr = FILE_BASE + 0x100000
    mu.mem_write(src_addr, src_data)

    mu.reg_write(UC_ARM_REG_R0, src_addr)
    mu.reg_write(UC_ARM_REG_R1, dst)
    mu.reg_write(UC_ARM_REG_SP, STACK_PTR)
    mu.reg_write(UC_ARM_REG_LR, 0)

    stopped = False

    def _hook(uc, address, size, user_data):
        nonlocal stopped
        if address == RETURN_ADDR:
            stopped = True
            uc.emu_stop()

    mu.hook_add(UC_HOOK_CODE, _hook)

    try:
        mu.emu_start(QMD_BASE, 0, timeout=30 * 1000000)
    except Exception:
        pass

    if not stopped:
        return None

    result_len = mu.reg_read(UC_ARM_REG_R0)
    return bytes(mu.mem_read(dst, result_len))


# ── Public API ────────────────────────────────────────

def decompress_chunk(data: bytes, engine_version: int,
                     engine_dir: str | Path | None = None) -> bytes:
    """
    Decompress a single compressed data chunk.

    Args:
        data: Compressed data
        engine_version: Engine version (e.g. 0xB4, 0xAD, 0x97)
        engine_dir: Engine file directory (auto-detected by default)

    Returns:
        Decompressed data

    Raises:
        FileNotFoundError: Engine file not found
        RuntimeError: Decompression failed or Unicorn not installed
    """
    engine = _load_engine(engine_version, engine_dir)
    if engine is None:
        raise FileNotFoundError(
            f"Engine file not found (version {engine_version:#04x}), "
            f"requires {ENGINE_FILES.get(engine_version, '?')}"
        )

    result = _decompress_arm(DRAM_BASE, data, engine)
    if result is None:
        raise RuntimeError("Decompression failed (timeout or exception)")
    return result


def decompress_file(filepath: str | Path,
                    output_dir: str | Path | None = None,
                    engine_dir: str | Path | None = None,
                    verbose: bool = True) -> int:
    """
    Decompress a single .so file.

    Args:
        filepath: Path to .so file
        output_dir: Output directory (defaults to same directory as input)
        engine_dir: Engine file directory
        verbose: Whether to print detailed info

    Returns:
        Total decompressed bytes, or -1 on failure
    """
    filepath = Path(filepath)
    filename = filepath.name

    if output_dir:
        outpath = Path(output_dir) / (filename + ".bin")
    else:
        outpath = filepath.with_suffix(filepath.suffix + ".bin")

    data = filepath.read_bytes()

    if len(data) < 0x28:
        if verbose:
            print(f"  {filename}: file too small")
        return -1

    # QRAM version
    qram1, qram2, qram3 = data[4], data[5], data[6]

    if verbose:
        print(f"  Decompressing {filename}  (Qram {qram1}.{qram2}.{qram3}) ...", end=" ")

    engine = _load_engine(qram3, engine_dir)
    if engine is None:
        if verbose:
            print(f"\n  ✗ Engine file missing (version {qram3:#04x})")
        return -1

    # Segment table
    offset = struct.unpack_from("<I", data, 0x20)[0]
    count  = struct.unpack_from("<I", data, 0x1C)[0]
    pos    = 0x28

    dst_addr = DRAM_BASE
    chunks: list[bytes] = []

    for _ in range(count):
        seg_off = struct.unpack_from("<I", data, pos)[0]
        seg_len_raw = struct.unpack_from("<I", data, pos + 4)[0]
        pos += 8

        src = offset + seg_off
        chunk = data[src : src + seg_len_raw]

        if seg_len_raw == 0x1000:
            # Uncompressed — copy directly
            result = chunk
        else:
            # ARM decompression
            result = _decompress_arm(dst_addr, chunk, engine)
            if result is None:
                if verbose:
                    print("✗ Decompression failed")
                return -1

        chunks.append(result)
        dst_addr += len(result)

    total_len = struct.unpack_from("<I", data, 0x0C)[0]
    if verbose:
        print(f"OK ({total_len} bytes)")

    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_bytes(b"".join(chunks))
    return total_len


def decompress_directory(sysfs_dir: str | Path,
                         output_dir: str | Path | None = None,
                         engine_dir: str | Path | None = None,
                         verbose: bool = True) -> int:
    """
    Decompress all .so files in a SystemFS directory.

    Automatically scans root, Osp/, and Shp/ subdirectories.

    Args:
        sysfs_dir: SystemFS directory path
        output_dir: Output directory (defaults to same structure as input)
        engine_dir: Engine file directory
        verbose: Whether to print detailed info

    Returns:
        Number of successfully processed files
    """
    sysfs_dir = Path(sysfs_dir)
    total = 0

    for sub in ["", "Osp", "Shp"]:
        search = sysfs_dir / sub
        if not search.is_dir():
            continue

        if verbose:
            print(f"\n--- /SystemFS/{sub or '(root)'} ---")

        files = sorted(
            p for p in search.iterdir()
            if p.is_file() and ".so" in p.name and not p.name.endswith(".bin")
        )

        for f in files:
            out_sub = Path(output_dir) / sub if output_dir else None
            ret = decompress_file(f, output_dir=out_sub, engine_dir=engine_dir,
                                  verbose=verbose)
            if ret >= 0:
                total += 1

    return total
