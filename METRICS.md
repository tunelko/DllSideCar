# Exploitability Scoring Model

DllSidecar ranks sideload candidates with a three-axis scorer
(`DllSidecar.Core/Services/ExploitabilityScorer.cs`). Each axis is
computed independently and capped at `0..10`. A weighted total drives
the final severity bucket shown in the UI.

## Design principles

- **Axes do not contaminate each other.** Exploitability never reads
  privesc severity. Impact never reads write-primitive feasibility.
  Confidence only carries evidence quality. This lets the UI rank and
  filter per axis without one signal masking another.
- **Every factor is logged.** Each contribution is recorded as a
  `ScoreFactor { Axis, Name, Points, Reason }` so the detail panel can
  drill down into why a candidate scored what it scored.
- **Negative factors are first-class.** Penalties (signed DLL,
  `LOAD_LIBRARY_SEARCH_SYSTEM32`, no exports) are stored alongside
  bonuses so the explanation reads as a balance sheet, not a hidden
  subtraction.

## The three axes

### 1. Exploitability (0..10)

How feasible is dropping a payload that the loader will pick up. Two
code paths feed this axis: `ScoreExistingExploitability` (target DLL is
on disk) and `ScorePhantomExploitability` (target slot is empty —
phantom DLL).

| Factor                  | Mode      | Points | Trigger                                                                |
|-------------------------|-----------|-------:|------------------------------------------------------------------------|
| `LowPrivWritable`       | Existing  |    +4  | Directory writable by non-admin principals                             |
| `LowPrivWritable`       | Phantom   |    +3  | Importer directory writable by non-admin                               |
| `CurrentUserWritable`   | Both      |  +2/+1 | Directory writable by current process only                             |
| `NotWritable`           | Existing  |     0  | No write primitive (logged for transparency)                           |
| `NotWritable`           | Phantom   |    -3  | Phantom is useless without a write primitive                           |
| `PhantomSlot`           | Phantom   |    +5  | Loader search path has no file — clean primitive                       |
| `NoImporter`            | Existing  |    -5  | No PE in directory imports the DLL — unlikely to load                  |
| `HasImporter`           | Existing  |    +2  | One or more importers found                                            |
| `SignedImporter`        | Both      |    +1  | At least one importer is Authenticode-trusted                          |
| `System32OnlyForced`    | Existing  |    -5  | Every importer sets `LOAD_LIBRARY_SEARCH_SYSTEM32` (0x800)             |
| `System32OnlyForced`    | Phantom   |    -6  | Same, harder penalty since phantom relies on directory search          |
| `DelayLoadOnly`         | Phantom   |    -2  | All references are delay-load — only fires if code calls into it       |
| `UnsignedDll`           | Existing  |    +2  | Target DLL unsigned or signature invalid                               |
| `SignedDll`             | Existing  |    -2  | Target is Authenticode-signed — replacement may trip integrity checks  |
| `UntrustedDll`          | Existing  |    +1  | Signed but chain is untrusted — replacement still viable               |
| `NoExports`             | Existing  |    -2  | DLL has no exports — only `DllMain` reachable, proxy out of scope      |
| `NamedExports`          | Existing  |    +1  | At least one named export available for proxying                       |

The sum is clamped to `[0, 10]`.

### 2. Impact (0..10)

What privilege is gained if the chain fires. Driven exclusively by
`PrivescContext.HighestSeverity` from the privesc detectors. Mapping is
fixed and documented in code (`ScoreImpact`):

| Privesc severity   | Impact | Factor name              |
|--------------------|-------:|--------------------------|
| `Critical`         |   10   | `ImpactSystemJackpot`    |
| `High`             |    8   | `ImpactSystem`           |
| `Medium`           |    5   | `ImpactAutoElevate`      |
| `Low`              |    3   | `ImpactLow`              |
| `Informational`    |    2   | `ImpactInformational`    |
| `None`             |    1   | `ImpactUserExec`         |

Note the `1` floor — even with no privesc path, a successful sideload
yields code execution in the user's context, which is not zero-impact.

### 3. Confidence (0..10)

Quality of the evidence backing the finding. Starts at a static-floor
and is upgraded by `ApplyDynamicEvidence()` after ProcMon or runtime
ETW correlation runs.

| `ConfidenceLevel`     | Confidence | When                                                                   |
|-----------------------|-----------:|------------------------------------------------------------------------|
| `StaticOnly`          | 1 or 3     | No runtime signal. `1` if no importer graph, `3` if importer resolved. |
| `RuntimeNameMatch`    | 7 or 8     | Runtime source saw the DLL resolved, but in a different directory.     |
| `RuntimeDirMatch`     | 9 or 10    | Runtime source saw it in this exact directory — ground truth.          |

The `+1` bumps inside each tier reward Runtime ETW over ProcMon CSV
ingest, and reward observing a miss inside the writable directory
(missing-file event) over a benign load.

`ApplyDynamicEvidence` is **idempotent** — repeated calls drop the
previous Confidence factors and re-apply, so re-correlating after a
fresh ProcMon capture does not double-count.

## Total and severity

```
Total = round(
    Exploitability * 0.50  +
    Impact         * 0.30  +
    Confidence     * 0.20)
```

The weights are constants on `ScoreBreakdown` (`WeightExploitability`,
`WeightImpact`, `WeightConfidence`). Exploitability dominates so the
tool surfaces "actually exploitable" findings first; Impact is the
secondary sort; Confidence pulls weight up only when evidence has been
validated, but never eclipses a high-exploit finding that has not yet
been dynamically validated.

Severity buckets (`ScoreBreakdown.Severity`):

| Total  | Severity   |
|-------:|------------|
| `>= 9` | Critical   |
| `>= 7` | High       |
| `>= 4` | Medium     |
| `>= 1` | Low        |
| `0`    | None       |

## Attack chain

`BuildChain` populates `PrivescContext.ChainSteps` with a structured
walk:

1. **Write primitive** — low-priv writable / user-writable / none
2. **Load vector** — phantom slot, signed importer, or unsigned importer
3. **Trigger** — scheduled task, service (with `ServiceDll`/wrapper
   detail), updater heuristic, autoElevate manifest, etc.
4. **Privilege** — derived from the highest-severity finding's
   severity tier
5. **Runtime evidence** *(optional)* — appended by
   `ApplyDynamicEvidence` when ProcMon or runtime ETW confirmed the
   resolve. The label includes the source (`Runtime trace` or
   `ProcMon`) and whether the match was by name or by exact directory.

`ChainSummary` is a single-line `→`-joined render of the steps that
the UI shows next to the candidate.

## Where to look in code

- `DllSidecar.Core/Services/ExploitabilityScorer.cs` — the scorer.
- `DllSidecar.Core/Models/ScoreBreakdown.cs` — axes, weights,
  severity buckets, factor log.
- `DllSidecar.Core/Models/Privesc/PrivescVector.cs` — privesc
  severity enum that drives Impact.
- `DllSidecar.Core/Services/ProcmonCorrelator.cs` and the runtime ETW
  tracer — sources of `DynamicEvidence` consumed by
  `ApplyDynamicEvidence`.
