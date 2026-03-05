# WinZOX

**WinZOX** is a file archiver focused on **own file format**, a **clean CLI**, and an internal architecture that stays maintainable as features grow.

> Status: **Active development**

---

## Why WinZOX
- **C++ performance**: predictable speed + easier native integration.
- **Modular architecture** to keep compression, archive, extraction, and crypto layers clean.
- **Practical UX** with progress reporting, speed/ETA, and shell integration on Windows.

---

## Features
### Current

- Create / extract archives via CLI

- `.zox` create + extract

- `.zip` create + extract

- `.7z` / `.rar` extract support

- Compression presets (Fast / Normal / Maximum / Ultra)

- Per-operation progress reporting (where supported)

- Encryption options: **AES-256** and **Gorgon**

- Archive integrity checks (including hash-based verification)

### Planned
- Multi-format support (ZIP / 7Z / RAR extract, etc.)
- Multi-thread compression where applicable (e.g., zstd)
- Archive integrity + metadata
- GUI frontend (optional)

---

## Supported Formats
| Format | Create | Extract | Notes |

|---|---:|---:|---|

| `.zox` | Yes | Yes | WinZOX native format |

| `.zip` | Yes | Yes | Standard ZIP workflow |

| `.7z` | No | Yes | Extract-only |

| `.rar` | No | Yes | Extract-only |

> `.zox` is WinZOX native format.
---

## Compression Presets (zstd defaults)
These are **recommended defaults** for a modern archiver:

| Preset | zstd level | Goal |

| Fast | 5 | very fast, decent ratio |

| Normal | 8 | balanced default |

| Maximum | 15 | smaller archive, slower |

| Ultra | 20 | strongest compression, much slower |

---

## Build
### Requirements
- C++17-compatible compiler
- CMake 3.10+
- Required libraries installed in your environment (for example: OpenSSL, zlib, zstd, libarchive)

### Build (CMake)
```bash
# Clone repository
git clone https://github.com/neofilisoft/WinZOX.git
cd WinZOX
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
