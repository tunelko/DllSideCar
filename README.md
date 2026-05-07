<p align="center">
  <img src="DllSidecar.GUI/Assets/dllsidecar.png" alt="DllSidecar" width="420">
</p>

# DllSidecar

A Windows desktop application for DLL sideloading and DLL hijacking
research (CWE-427, CWE-426). It automates static PE analysis,
candidate scanning, dynamic correlation with Process Monitor and ETW,
proof-of-concept C source generation, MinGW compilation, and the full
advisory authoring lifecycle (Markdown / INCIBE CNA / GHSA), with a
persisted case library and a multi-format export pipeline.

The tool targets independent vulnerability researchers who need a
reproducible end-to-end workflow from "I just installed software X"
to "I have a complete, vendor-ready advisory packet".

## Features

### Static analysis

- **PE inspection** via PeNet 5: imports, exports, signature, version
  info, security flags (ASLR, DEP, CFG, SafeSEH).
- **Sideload candidate scanner**: walks an installation directory,
  identifies signed executables that import unsigned DLLs without
  absolute paths, and ranks results by exploitability.
- **Phantom DLL detector**: enumerates imports referenced by the IAT
  but not present on disk, the highest-value class of sideload
  candidates.
- **Directory ACL checker**: flags writable-by-non-admin directories
  that would let a low-privileged user plant a payload.

### Dynamic correlation

- **Process Monitor CSV ingest**: parses ProcMon exports, joins
  `NAME NOT FOUND` entries against the static scan output, and
  surfaces the actual runtime DLL search order.
- **Live ETW tracer** (admin): real-time monitoring of LoadLibrary
  failures across selected processes, with per-DLL aggregation and a
  process tree view.
- **Installer extraction**: statically unpacks `.msi`, Inno Setup,
  NSIS, and 7-Zip self-extracting executables without execution.

### Code generation

- **Export tracer**: wraps every export of a target DLL with a logger
  so the host process tells you which exports it actually calls.
- **DLL proxy**: forwards exports to a renamed original and fires a
  payload from a configurable export. Supports D/Invoke, direct
  syscalls, encrypted strings, and assembly trampolines.
- **DLL sideload stub**: one-shot non-forwarding payload in `DllMain`
  for phantom and replacement scenarios.
- **DJB2 hash calculator** with XOR key display for API-hash
  obfuscation work.

### Build pipeline

- **MinGW wrapper** (`gcc` + `windres`): compiles generated C and
  resource files into a final DLL. Supports timestamp stomping for
  binary cosmetic mimicry.
- **Toolkit health check**: detects and validates ProcMon, sigcheck,
  Dependencies, x64dbg, x32dbg, Python, 7-Zip, InnoUnp, MinGW, and
  the NVD API key state.

### Advisory authoring

- **Three render targets**: Markdown (with HTML preview via Markdig),
  INCIBE CNA, and GHSA. Each format is treated as an independent
  artifact with its own status workflow.
- **CVSS v3.1 and v4.0 calculators** with vector parsing, score
  recomputation, and qualitative severity output.
- **Case library** (SQLite): persisted advisory records, per-vendor
  human-readable filenames (`<VULN_TYPE>_ADVISORY_<NNNN>.<ext>`),
  per-artifact status timeline, drag-and-drop vendor reorganization,
  and bundle export/import (`.dsa`).
- **NVD CVE deduplication**: optional automatic lookup against the
  National Vulnerability Database before reporting, to avoid
  duplicating already-disclosed findings.

### Operational

- **Self-hardened P/Invokes**: every native import is restricted to
  `System32` via `[assembly: DefaultDllImportSearchPaths]`, so the
  tool itself is not vulnerable to the same class of attack it
  researches.
- Dark theme, collapsible navigation rail, dockable console, and a
  guided multi-stage research wizard.

## Architecture

Three-project solution targeting `.NET 9.0`:

| Project                      | Purpose                                              |
|------------------------------|------------------------------------------------------|
| `DllSidecar.Core`            | Domain models, services, PE analysis, code gen, repository. Zero UI dependencies. |
| `DllSidecar.GUI`             | WPF shell, navigation, all dialogs and pages.        |
| `DllSidecar.Core.Tests`      | xUnit suite for analyzers, validators, and detectors.|

Data flow: `AnalyzePage` (or `ScanPage`) populates session state on
the main window, which `GeneratePage` consumes to emit C source and
`BuildPage` compiles via the MinGW wrapper. Output of any phase can
be promoted to an advisory record in the persisted library.

## Build

### Prerequisites

- Windows 10 or 11
- .NET SDK 9.0.300 or newer
- Optional, for full runtime functionality:
  - MinGW-w64 (via MSYS2): required to compile generated PoC DLLs
  - Sysinternals suite: required for ProcMon CSV ingest and
    sigcheck-based signature verification
  - Python 3.10+: required for installer extraction helpers

### Commands

```
dotnet restore DllSidecar.sln
dotnet build DllSidecar.sln --configuration Release
dotnet run --project DllSidecar.GUI
```

### Tests

```
dotnet test DllSidecar.Core.Tests/DllSidecar.Core.Tests.csproj --configuration Release
```

## Disclaimer

DllSidecar is a personal-use research tool built and maintained by the
author for identifying Windows applications susceptible to DLL
Sideloading and Proxy Sideloading (CWE-427, CWE-426). It is used in
day-to-day defensive research to surface potential local privilege
escalation paths, with the goal of coordinated disclosure to affected
vendors.

The tool is provided as-is, for lawful security research, authorized
testing, and educational purposes only. Use against software, systems,
or environments for which you do not have explicit permission is your
sole responsibility. The author assumes no liability for misuse or for
any direct or indirect damage arising from its use.
