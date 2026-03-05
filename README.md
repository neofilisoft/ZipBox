# WinZOX

**WinZOX** is a file archiver focused on **own file format**, a **clean CLI**, and an internal architecture that stays maintainable as features grow.

> Status: **Work in progress**

---

## Why ZOX
- **C++ performance**: predictable speed + easier native integration.
- **Modular design**: add codecs/formats without turning the codebase into spaghetti.
- **Practical UX**: progress, speed, ETA, cancel but without the drama.

---

## Features
### Current / In Progress
- Archive **create / extract** workflow (CLI)
- **Progress reporting** (total + per-file), speed, ETA
- **Compression presets** (fast/normal/maximum/ultra)
- Solid foundation for multi-format support (see Roadmap)

### Planned
- Multi-format support (ZIP / 7Z / RAR extract, etc.)
- Multi-thread compression where applicable (e.g., zstd)
- Archive integrity + metadata
- GUI frontend (optional)

> If a feature is missing, assume it’s **planned** rather than “broken”.

---

## Supported Formats
| Format | Create | Extract | Notes |
|---|---:|---:|---|
| `.zip` |Yes  |Yes | Standard |
| `.7z`  | —  | Yes | Extract-only |
| `.rar` | —  | Yes | Extract-only |
| `.zox` | Yes | Yes | If you use a custom container |

> ZOX is a WinZOX format.
---

## Compression Presets (zstd example)
These are **recommended defaults** for a modern archiver:

| Preset | zstd level | Goal |
|---|---:|---|
| Fast | 5 | very fast, decent ratio |
| Normal | 8 | best general-purpose balance |
| Maximum | 15 | smaller archives, slower |
| Ultra | 20 | extreme compression, much slower |

> Notes:
> - For tiny files, overhead can dominate; don’t expect miracles.

---

## Build
### Requirements
- C++ compiler with C++17+ support
- CMake (recommended)

### Build (CMake)
```bash
git clone https://github.com/neofilisoft/ZipBox.git
cd ZipBox
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
