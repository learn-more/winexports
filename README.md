# winexports

Static Hugo documentation site for Windows DLL exports across multiple Windows versions.

Features:
- Browse all DLL exports with ordinal numbers, per Windows version
- See forwarder exports (shown as → target)
- Search the full function index to find which DLLs export a given function
- Per-function pages showing which DLLs export it across versions (useful for tracking API moves between DLLs)

## Windows versions

| Directory | Description |
|-----------|-------------|
| `data/exports/nt52_x86`        | Windows Server 2003 x86 (build 3790) |
| `data/exports/nt61_x86`        | Windows 7 x86 (build 7601) |
| `data/exports/nt61_x64`        | Windows 7 x64 (build 7601) |
| `data/exports/nt100_x86_26200` | Windows 11 x86 (build 26200) |

## Local workflow

### 1. Extract exports from a Windows installation

```
python scripts\dump_exports.py input_dir data\exports\nt61_x86 include_files.txt
```

### 2. Generate Hugo content from the JSON data

```
python scripts\generate_hugo_content.py
```

This regenerates the following (all gitignored — do not edit by hand):

| Output | Description |
|--------|-------------|
| `data/dlls/` | Aggregated per-DLL data for Hugo templates |
| `content/dlls/` | One Hugo page per DLL |
| `static/data/fn/` | Per-function cross-reference JSON (multi-DLL functions only) |
| `static/data/function_names.json` | Full function name list for client-side search |

### 3. Build or preview

```
hugo server   # local preview at http://localhost:1313
hugo          # production build into public/
```
