# WinExports

Static Hugo documentation site for Windows DLL exports across multiple Windows versions.

Features:
- Browse all DLL exports with ordinal numbers, per Windows version
- See forwarder exports (shown as → target)
- Search the full function index to find which DLLs export a given function
- Per-function pages showing which DLLs export it across versions (useful for tracking API moves between DLLs)

## Windows versions

| Directory | Description |
|-----------|-------------|
| `data/exports/nt51_x86`        | Windows XP x86 (build 2600) |
| `data/exports/nt52_x86`        | Windows Server 2003 x86 (build 3790) |
| `data/exports/nt60_x86`        | Windows Vista x86 (build 6002) |
| `data/exports/nt61_x64`        | Windows 7 x64 (build 7601) |
| `data/exports/nt63_x86`        | Windows 8.1 x86 (build 9600) |
| `data/exports/nt63_x64`        | Windows 8.1 x64 (build 9600) |
| `data/exports/nt100_x64_19041` | Windows 10 x64 (build 19041) |
| `data/exports/nt100_x64_26200` | Windows 11 x64 (build 26200) |

## Local workflow

### 1. Extract DLLs from Windows ISO files

Configure `ISO_DIR`, `OUTPUT_DIR`, and `SEVENZIP` at the top of the script, then:

```
uv run scripts\01-extract_dlls.py [--force]
```

### 2. Dump exports from the extracted DLLs

```
uv run scripts\02-dump_exports.py <input_directory>
```

### 3. Generate Hugo content from the JSON data

```
uv run scripts\03-generate_hugo_content.py
```

This regenerates the following (all gitignored — do not edit by hand):

| Output | Description |
|--------|-------------|
| `content/_index.md` | Site home page with version table |
| `data/versions.json` | Version metadata (label, desc) for Hugo templates |
| `data/dlls/` | Aggregated per-DLL data for Hugo templates |
| `content/dlls/` | One Hugo page per DLL |
| `static/data/fn/` | Per-function cross-reference JSON (multi-DLL functions only) |
| `static/data/function_names.json` | Full function name list for client-side search |

### 3. Build or preview

```
hugo server   # local preview at http://localhost:1313
hugo          # production build into public/
```
