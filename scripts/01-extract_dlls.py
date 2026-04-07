#!/usr/bin/env python3
"""
01-extract_dlls.py  (step 1 of 3 in the WinExports pipeline)

Scans an ISO directory for .iso files and extracts Windows\\System32 files
(dll, exe, cpl, ocx, drv, sys) into per-version subfolders ready for
02-dump_exports.py.

Output folder naming: nt{major}{minor}_{arch}[_{build}]
    Build suffix is required for NT 10.0 (Win10 / Win11), omitted otherwise.

Requirements:
    - 7-Zip at C:\\Program Files\\7-Zip\\7z.exe
    - Python 3.6+  (stdlib only)
    - Sufficient temp + output disk space
"""

import argparse
import os
import shutil
import sys
import struct
import tempfile
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────
ISO_DIR    = Path(r'D:\iso')
OUTPUT_DIR = Path(r'D:\dlls')
SEVENZIP   = r'C:\Program Files\7-Zip\7z.exe'
# ─────────────────────────────────────────────────────────────────────────────


def run(args, **kwargs):
    """Run subprocess; tolerates 7z exit code 1 (warnings)."""
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
        **kwargs,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f'Command failed (rc={result.returncode}):\n'
            f'  cmd : {" ".join(str(a) for a in args)}\n'
            f'  stderr: {result.stderr[:600]}'
        )
    return result


# ── ISO classification ────────────────────────────────────────────────────────

def list_iso_top_level(iso_path):
    """
    Return (all_entries_lower, root_dirs_upper) from 7z listing.
    all_entries_lower  : set of all paths in the ISO, lowercased, with backslashes
    root_dirs_upper    : set of root-level directory names, uppercased
    """
    r = run([SEVENZIP, 'l', str(iso_path)])
    all_entries = set()
    root_dirs   = set()
    for line in r.stdout.splitlines():
        # 7z l output has two distinct row shapes:
        #   file : date time attr size compressed name  (6 parts)
        #   dir  : date time attr name                  (4 parts — no size columns)
        parts = line.split()
        if len(parts) < 4:
            continue
        attr = parts[2]
        # Validate attr field looks like a 7z attribute string (5 chars, [D.][R.][H.][S.][A.])
        if len(attr) != 5 or not all(c in 'DRHSA.' for c in attr):
            continue
        path = parts[-1].replace('/', '\\')
        path_lower = path.lower()
        all_entries.add(path_lower)
        # Root-level directory: attr starts with D, no separator in path
        if attr.startswith('D') and '\\' not in path and '/' not in path:
            root_dirs.add(path.upper())
    return all_entries, root_dirs


def classify_iso(iso_path):
    """
    Returns one of:
      ('wim',  inner_path)   – WIM/ESD pipeline; inner_path uses backslashes
      ('i386', None)         – I386/DL_ pipeline (XP / Server 2003 CD1)
      ('skip', reason_str)   – supplemental disc or unrecognised content
    """
    all_entries, root_dirs = list_iso_top_level(iso_path)

    # WIM/ESD takes priority
    for candidate in (
        'sources\\install.wim',
        'sources\\install.esd',
    ):
        if candidate in all_entries:
            return ('wim', candidate)

    # I386 layout (XP / Server 2003 CD1)
    if 'I386' in root_dirs:
        return ('i386', None)

    # Supplemental / driver disc — nothing useful here
    has_cmpnt = any(d.startswith('CMPNENTS') for d in root_dirs)
    reason = ('supplemental R2 components disc' if has_cmpnt
              else 'no recognised OS content (no WIM/ESD, no I386)')
    return ('skip', reason)


# ── Folder naming ─────────────────────────────────────────────────────────────

def make_folder_name(major, minor, build, arch):
    """
    nt{major}{minor}_{arch}[_{build}]
    Build is mandatory for NT 10.0 (covers Win10 and Win11).
    """
    base = f'nt{major}{minor}_{arch}'
    if major == 10:
        return f'{base}_{build}'
    return base


# ── WIM/ESD pipeline ──────────────────────────────────────────────────────────

def read_wim_xml(wim_path):
    """
    Read the embedded XML metadata block from a WIM or ESD file.
    The XML resource descriptor sits at offset 72 in the 208-byte header:
      bytes  0-7  : packed (bits 0-55 = data size, bits 56-63 = flags)
      bytes  8-15 : file offset of XML data
      bytes 16-23 : original (uncompressed) size  [same as data size for XML]
    The XML is always stored uncompressed (no decompression needed).
    """
    with open(wim_path, 'rb') as f:
        hdr = f.read(208)
    if hdr[:8] != b'MSWIM\x00\x00\x00':
        raise ValueError(f'Not a WIM/ESD file (bad magic): {wim_path}')
    packed     = struct.unpack_from('<Q', hdr, 72)[0]
    xml_size   = packed & 0x00FFFFFFFFFFFFFF
    xml_offset = struct.unpack_from('<Q', hdr, 80)[0]
    with open(wim_path, 'rb') as f:
        f.seek(xml_offset)
        raw = f.read(int(xml_size))
    # Decode UTF-16; strip BOM if present
    if raw[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return raw.decode('utf-16')
    return raw.decode('utf-16-le')


def parse_wim_metadata(xml_str):
    """
    Extract (major, minor, build, arch_str) from WIM XML.
    Uses IMAGE INDEX="1" — consistent across multi-edition WIMs.
    ARCH: 0 = x86, 9 = AMD64/x64.
    """
    root = ET.fromstring(xml_str)
    img1 = None
    for img in root.findall('IMAGE'):
        if img.get('INDEX') == '1':
            img1 = img
            break
    if img1 is None:
        raise ValueError('No IMAGE INDEX="1" in WIM XML')
    win = img1.find('WINDOWS')
    if win is None:
        raise ValueError('No <WINDOWS> element in IMAGE 1')
    major     = int(win.findtext('VERSION/MAJOR', '0'))
    minor     = int(win.findtext('VERSION/MINOR', '0'))
    build     = int(win.findtext('VERSION/BUILD', '0'))
    arch_code = int(win.findtext('ARCH', '0'))
    arch      = 'x64' if arch_code == 9 else 'x86'
    return major, minor, build, arch


def process_wim_iso(iso_path, wim_inner, temp_dir, output_dir, force=False):
    """
    WIM/ESD pipeline:
      1. Extract WIM/ESD from ISO to temp_dir
      2. Read XML metadata → compute output folder name
      3. Skip if output already populated
      4. Extract System32 DLLs (flat) into output subfolder
    """
    print(f'  [WIM] Extracting {wim_inner} from ISO ...')
    run([SEVENZIP, 'e', str(iso_path),
         f'-o{temp_dir}', wim_inner, '-y'])

    wim_file = Path(temp_dir) / Path(wim_inner).name
    if not wim_file.exists():
        raise FileNotFoundError(f'Expected {wim_file} after ISO extraction')

    xml_str = read_wim_xml(wim_file)
    major, minor, build, arch = parse_wim_metadata(xml_str)
    print(f'  [WIM] Detected: NT {major}.{minor} build {build} {arch}')

    folder_name = make_folder_name(major, minor, build, arch)
    dest = output_dir / folder_name

    if dest.exists() and any(dest.iterdir()):
        if not force:
            print(f'  [SKIP] {dest} already populated — skipping.')
            return
        print(f'  [FORCE] Removing existing {dest} ...')
        shutil.rmtree(dest)

    dest.mkdir(parents=True, exist_ok=True)
    print(f'  [WIM] Extracting System32 files → {dest} ...')
    exts = ('dll', 'exe', 'cpl', 'ocx', 'drv', 'sys')
    patterns = [rf'1\Windows\System32\*.{e}' for e in exts]
    run([SEVENZIP, 'e', str(wim_file), f'-o{dest}', *patterns, '-y'])
    file_count = sum(1 for f in dest.iterdir()
                     if f.suffix.lower().lstrip('.') in exts)
    print(f'  [WIM] Done — {file_count} files in {dest}')


# ── I386/DL_ pipeline ─────────────────────────────────────────────────────────

def parse_pe_version_arch(dll_bytes):
    """
    Read (major, minor, build, arch_str) from a PE binary.
    Arch  : COFF machine word at e_lfanew+4  (0x014c=x86, 0x8664=x64)
    Version: VS_FIXEDFILEINFO located by magic dword 0xFEEF04BD
    """
    e_lfanew = struct.unpack_from('<I', dll_bytes, 60)[0]
    machine  = struct.unpack_from('<H', dll_bytes, e_lfanew + 4)[0]
    arch = {0x014c: 'x86', 0x8664: 'x64', 0x0200: 'ia64'}.get(machine, 'x86')

    # VS_FIXEDFILEINFO dwSignature stored little-endian = \xbd\x04\xef\xfe
    sig = b'\xbd\x04\xef\xfe'
    idx = dll_bytes.find(sig)
    if idx < 0:
        raise ValueError('VS_FIXEDFILEINFO signature not found in PE binary')
    fvms  = struct.unpack_from('<I', dll_bytes, idx + 8)[0]
    fvls  = struct.unpack_from('<I', dll_bytes, idx + 12)[0]
    major = (fvms >> 16) & 0xFFFF
    minor =  fvms        & 0xFFFF
    build = (fvls >> 16) & 0xFFFF
    return major, minor, build, arch


def process_i386_iso(iso_path, temp_dir, output_dir, force=False):
    """
    I386/DL_ pipeline (XP, Server 2003 CD1):
      1. Extract NTDLL.DLL for version/arch detection
      2. Compute output folder name; skip if already populated
      3. Extract all I386\\*.DL_ to a staging dir
      4. Batch-expand via expand.exe -R
    """
    print(f'  [I386] Extracting NTDLL.DLL for version detection ...')
    ntdll_dir = Path(temp_dir) / 'ntdll'
    ntdll_dir.mkdir(exist_ok=True)
    run([SEVENZIP, 'e', str(iso_path),
         f'-o{ntdll_dir}',
         'I386/SYSTEM32/NTDLL.DLL', '-y'])

    ntdll_path = ntdll_dir / 'NTDLL.DLL'
    if not ntdll_path.exists():
        raise FileNotFoundError(
            f'NTDLL.DLL not found after extraction from {iso_path.name}')

    with open(ntdll_path, 'rb') as f:
        dll_bytes = f.read()
    major, minor, build, arch = parse_pe_version_arch(dll_bytes)
    print(f'  [I386] Detected: NT {major}.{minor} build {build} {arch}')

    folder_name = make_folder_name(major, minor, build, arch)
    dest = output_dir / folder_name

    if dest.exists() and any(dest.iterdir()):
        if not force:
            print(f'  [SKIP] {dest} already populated — skipping.')
            return
        print(f'  [FORCE] Removing existing {dest} ...')
        shutil.rmtree(dest)

    dest.mkdir(parents=True, exist_ok=True)

    staging = Path(temp_dir) / 'dl_staging'
    staging.mkdir(exist_ok=True)
    print(f'  [I386] Extracting I386 compressed files to staging dir ...')
    # Compressed variants: DL_=dll, EX_=exe, CP_=cpl, OC_=ocx, DR_=drv, SY_=sys
    compressed_patterns = [
        'I386/*.DL_', 'I386/*.EX_', 'I386/*.CP_',
        'I386/*.OC_', 'I386/*.DR_', 'I386/*.SY_',
    ]
    run([SEVENZIP, 'e', str(iso_path),
         f'-o{staging}',
         *compressed_patterns, '-y'])

    expand_exe = r'C:\Windows\System32\expand.exe'
    compressed_suffixes = ('DL_', 'EX_', 'CP_', 'OC_', 'DR_', 'SY_')
    for suffix in compressed_suffixes:
        pattern = str(staging / f'*.{suffix}')
        result = subprocess.run(
            [expand_exe, '-R', pattern, str(dest)],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f'  [WARN] expand.exe *.{suffix} returned {result.returncode}: '
                  f'{result.stderr[:200]}')

    # Some files (e.g. NTDLL.DLL) are stored uncompressed in I386\ — extract directly
    print(f'  [I386] Extracting uncompressed I386 files → {dest} ...')
    uncompressed_patterns = [
        'I386/*.DLL', 'I386/*.EXE', 'I386/*.CPL',
        'I386/*.OCX', 'I386/*.DRV', 'I386/*.SYS',
    ]
    run([SEVENZIP, 'e', str(iso_path),
         f'-o{dest}',
         *uncompressed_patterns, '-y'])

    file_count = sum(1 for f in dest.iterdir()
                     if f.suffix.lower().lstrip('.') in
                        ('dll', 'exe', 'cpl', 'ocx', 'drv', 'sys'))
    print(f'  [I386] Done — {file_count} files in {dest}')


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Extract System32 files from Windows ISOs.')
    parser.add_argument('--force', action='store_true',
                        help='Delete and re-generate already-populated output folders.')
    args = parser.parse_args()

    if not Path(SEVENZIP).exists():
        sys.exit(f'ERROR: 7-Zip not found at {SEVENZIP}\n'
                 f'Install 7-Zip or update the SEVENZIP variable in this script.')

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    iso_files = sorted(ISO_DIR.glob('*.iso'))
    if not iso_files:
        sys.exit(f'No .iso files found in {ISO_DIR}')

    print(f'Found {len(iso_files)} ISO file(s) in {ISO_DIR}')
    print(f'Output directory: {OUTPUT_DIR}')
    if args.force:
        print('Mode: FORCE (existing folders will be wiped and regenerated)')
    print()

    for iso_path in iso_files:
        print(f'>>> {iso_path.name}')
        try:
            kind, detail = classify_iso(iso_path)

            if kind == 'skip':
                print(f'  [SKIP] {detail}\n')
                continue

            with tempfile.TemporaryDirectory(prefix='dll_extract_') as tmp:
                if kind == 'wim':
                    process_wim_iso(iso_path, detail, tmp, OUTPUT_DIR, force=args.force)
                elif kind == 'i386':
                    process_i386_iso(iso_path, tmp, OUTPUT_DIR, force=args.force)

        except Exception as exc:
            print(f'  [ERROR] {exc}')

        print()

    print('All done.')


if __name__ == '__main__':
    main()
