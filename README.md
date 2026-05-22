![DllSidecar](DllSidecar.GUI/Assets/dllsidecar.png)

# DllSidecar

A Windows desktop application for DLL sideloading and DLL hijacking
research (CWE-427, CWE-426). It automates static PE analysis,
candidate scanning, dynamic correlation with Process Monitor and ETW,
proof-of-concept C source generation, MinGW compilation, and the full
advisory authoring lifecycle (Markdown / GHSA), with a persisted case
library and a multi-format export pipeline.

The tool targets independent vulnerability researchers who need a
reproducible end-to-end workflow from "I just installed software X"
to "I have a complete, vendor-ready advisory packet".

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

## Features

### Static analysis

- **PE inspection** via PeNet 5: imports, exports, signature, version
  info, security flags (ASLR, DEP, CFG, SafeSEH).
- **Sideload candidate scanner**: walks an installation directory,
  identifies signed executables that import unsigned DLLs without
  absolute paths, and ranks results by exploitability via the
  three-axis [scoring model](METRICS.md).
- **Phantom DLL detector**: enumerates imports referenced by the IAT
  but not present on disk, the highest-value class of sideload
  candidates.
- **IAT callsite scanner**: walks `ImageImportDescriptors` →
  `FirstThunk` to locate where `LoadLibrary` is actually called, and
  extracts the resolved string argument plus `LoadLibraryEx` flags
  (`LOAD_LIBRARY_SEARCH_SYSTEM32`, etc.). Distinguishes
  *no imports* from *imports without observable callsites*.
- **Directory ACL checker**: flags writable-by-non-admin directories
  that would let a low-privileged user plant a payload.

### Dynamic correlation

- **Process Monitor CSV ingest**: parses ProcMon exports, joins
  `NAME NOT FOUND` entries against the static scan output, and
  surfaces the actual runtime DLL search order.
- **Live ETW tracer** (admin): real-time monitoring of LoadLibrary
  failures across selected processes, with per-DLL aggregation and a
  process tree view. Supports three modes (Launch / Attach / Watch),
  command-line filtering for svchost group disambiguation, a Service
  Picker that auto-fills Watch-by-Name, and a pulsing REC indicator
  while a session is live.
### Privilege escalation surface

- **Service DLL Audit modal**: enumerates installed services, surfaces
  candidates whose `ImagePath` or `ServiceDll` resolves out of a
  writable directory, and links each finding back to the candidate
  scanner.
- **Privesc detectors**: scheduled tasks (with wrapper resolution to
  the actual launched binary), services with `ServiceDll`, autoElevate
  manifests, updater heuristics, and `requireAdministrator` paths.

### Code generation

- **Unified DLL Techniques page**: single 3-column workflow (PAYLOAD /
  EVASION / POST-PROC) for Proxy and Sideload modes, mirrored in the
  guided research wizard.
- **Export tracer**: wraps every export of a target DLL with a logger
  so the host process tells you which exports it actually calls.
- **DLL proxy**: forwards exports to a renamed original and fires a
  payload from a configurable export. Supports D/Invoke, direct
  syscalls, encrypted strings, and assembly trampolines.
- **DLL sideload stub**: one-shot non-forwarding payload in `DllMain`
  for phantom and replacement scenarios.
- **Shellcode payload pattern**: `VirtualAlloc(RW)` →
  `RtlCopyMemory` → `VirtualProtect(RX)` → `CreateThread` (no RWX
  region, no direct cast on the calling thread). Mirrored across the
  default, D/Invoke, and direct-syscall paths.
- **Sandbox-escape payload**: cross-process inject + remote
  `CreateProcessA` on `WinSta0\Default` for AppContainer/LOW IL hosts
  (Acrobat, Office, Edge) where `WinExec` is policy-blocked.
- **DJB2 hash calculator** with XOR key display for API-hash
  obfuscation work.
- **Configurable defaults**: MessageBox PoC title and body editable
  from Configuration → Payload Defaults.

### Build pipeline

- **MinGW wrapper** (`gcc` + `windres`): compiles generated C and
  resource files into a final DLL. Supports timestamp stomping for
  binary cosmetic mimicry.
- **Toolkit health check**: detects and validates ProcMon, sigcheck,
  Dependencies, x64dbg, x32dbg, MinGW, and the NVD API key state.

### Advisory authoring

- **Two render targets**: Markdown (with HTML preview via Markdig) and
  GHSA. Each format is treated as an independent artifact with its own
  status workflow.
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

- **Guided research wizard** as the default landing page, with a
  HUNTING-FOR strip in the chrome and a stage indicator that mirrors
  the standalone DLL Techniques page.
- **Self-hardened P/Invokes**: every native import is restricted to
  `System32` via `[assembly: DefaultDllImportSearchPaths]`, so the
  tool itself is not vulnerable to the same class of attack it
  researches.
- Dark theme, collapsible navigation rail with active-page highlight,
  dockable console panel (collapsed by default, height persisted
  across sessions), Help → About dialog, native splash screen.

## Scoring model

Candidates are ranked by a three-axis scorer
(Exploitability / Impact / Confidence) with documented weights and a
per-axis factor log. See [METRICS.md](METRICS.md) for the full
breakdown — what each axis measures, every factor and its points, the
confidence tiers, and the total/severity formula.

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

DllSidecar performs a toolchain probe on every launch and surfaces a
modal warning when the MinGW compilers are not detected, so an empty
MSYS2 install (or a missing PATH entry) is caught before the user
spends time on a PoC that cannot be built. Analysis-only features
remain usable without the compiler.

### Compiler setup (MSYS2 / MinGW)

The code-generation pipeline emits portable C source that is compiled
into the proxy / sideload DLL by `gcc` from a MinGW-w64 toolchain. The
recommended way to obtain it on Windows is MSYS2.

1. **Install MSYS2.** Download the installer from
   [https://www.msys2.org/](https://www.msys2.org/) and accept the
   default install location (`C:\msys64`). The Inno Setup-style wizard
   takes about a minute.
2. **Open the MSYS2 UCRT64 (or MSYS2 MSYS) shell** from the Start
   menu. Bring the base system up to date first:
   ```bash
   pacman -Syu
   ```
   Re-open the shell if `pacman` asks to close the terminal after
   updating its own core packages, then run `pacman -Syu` once more to
   finish the upgrade.
3. **Install the 64-bit and 32-bit toolchains.** A single command
   installs both architectures plus `windres` (resource compiler used
   for metadata cloning):
   ```bash
   pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-i686-gcc
   ```
4. **Confirm the binaries exist.** DllSidecar probes the default MSYS2
   layout (`C:\msys64\mingw64\bin` and `C:\msys64\mingw32\bin`)
   automatically, but you can verify by listing them:
   ```
   C:\msys64\mingw64\bin\x86_64-w64-mingw32-gcc.exe --version
   C:\msys64\mingw32\bin\i686-w64-mingw32-gcc.exe --version
   ```
5. **Override the paths** in DllSidecar's *Configuration → MinGW*
   section only if you installed MSYS2 to a non-default location. The
   defaults match a vanilla `C:\msys64` install.

Once the compilers resolve, the startup warning disappears and the
status bar at the top of the main window shows `GCC X64 — OK` /
`WINDRES — OK` in green.

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
