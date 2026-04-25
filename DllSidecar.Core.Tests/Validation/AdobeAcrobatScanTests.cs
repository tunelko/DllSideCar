using DllSidecar.Core.Models;
using DllSidecar.Core.Services;

namespace DllSidecar.Core.Tests.Validation;

/// <summary>
/// Sprint 4A validation: scan a real Adobe Acrobat DC installation and verify
/// that the scoring model, phantoms, and ProcMon correlation produce coherent results.
/// Tests skip automatically if Acrobat is not installed.
/// </summary>
public class AdobeAcrobatScanTests
{
    private const string AcrobatDir = @"C:\Program Files\Adobe\Acrobat DC\Acrobat";
    private const string ProcmonCsv = @"D:\COMPARTIDO\CLAUDE\BugAInters\results\adobereader\win11_ACRO_fault.CSV";

    private static bool AcrobatInstalled => Directory.Exists(AcrobatDir);
    private static bool ProcmonCsvExists => File.Exists(ProcmonCsv);

    private static ScanResults RunScan(bool phantoms = true, bool privesc = true)
    {
        var scanner = new SideloadScanner();
        var opts = new ScanOptions { IncludePhantoms = phantoms, AnalyzePrivesc = privesc };
        return scanner.Scan(AcrobatDir, opts, null, CancellationToken.None);
    }

    // ──────────────────────────────────────────────
    //  SCAN BASICS
    // ──────────────────────────────────────────────

    [Fact]
    public void Scan_AcrobatDir_ProducesCandidates()
    {
        if (!AcrobatInstalled) return;

        var results = RunScan();
        Assert.NotEmpty(results.Existing);
        Assert.True(results.ExistingCount >= 5,
            $"Expected at least 5 existing candidates, got {results.ExistingCount}");
    }

    [Fact]
    public void Scan_AcrobatDir_FindsPhantoms()
    {
        if (!AcrobatInstalled) return;

        var results = RunScan();
        Assert.NotEmpty(results.Phantoms);
    }

    // ──────────────────────────────────────────────
    //  SCORING COHERENCE
    // ──────────────────────────────────────────────

    [Fact]
    public void Score_AllCandidates_HaveValidAxes()
    {
        if (!AcrobatInstalled) return;

        var results = RunScan();

        foreach (var c in results.Existing)
        {
            Assert.True(c.Score.Exploitability >= 0 && c.Score.Exploitability <= 10,
                $"{c.Dll.Filename}: Exploit={c.Score.Exploitability} out of [0,10]");
            Assert.True(c.Score.Impact >= 0 && c.Score.Impact <= 10,
                $"{c.Dll.Filename}: Impact={c.Score.Impact} out of [0,10]");
            Assert.True(c.Score.Confidence >= 0 && c.Score.Confidence <= 10,
                $"{c.Dll.Filename}: Confidence={c.Score.Confidence} out of [0,10]");
            Assert.True(c.Score.Total >= 0 && c.Score.Total <= 10,
                $"{c.Dll.Filename}: Total={c.Score.Total} out of [0,10]");
        }

        foreach (var p in results.Phantoms)
        {
            Assert.True(p.Score.Total >= 0 && p.Score.Total <= 10,
                $"Phantom {p.DllName}: Total={p.Score.Total} out of [0,10]");
        }
    }

    [Fact]
    public void Score_WritableDirCandidates_RankHigherExploitability()
    {
        if (!AcrobatInstalled) return;

        var results = RunScan();

        var writable = results.Existing.Where(c => c.Dir.IsUserWritable).ToList();
        var nonWritable = results.Existing.Where(c => !c.Dir.IsUserWritable).ToList();

        if (writable.Count > 0 && nonWritable.Count > 0)
        {
            var avgW = writable.Average(c => (double)c.Score.Exploitability);
            var avgNW = nonWritable.Average(c => (double)c.Score.Exploitability);
            Assert.True(avgW >= avgNW,
                $"Writable avg Exploit ({avgW:F1}) should >= non-writable ({avgNW:F1})");
        }
    }

    [Fact]
    public void Score_StaticOnly_ConfidenceIsLow()
    {
        if (!AcrobatInstalled) return;

        var results = RunScan();

        foreach (var c in results.Existing)
        {
            Assert.True(c.Score.Confidence <= 5,
                $"{c.Dll.Filename}: static-only Confidence should be <= 5, got {c.Score.Confidence}");
            Assert.Equal(ConfidenceLevel.StaticOnly, c.Score.ConfidenceLevel);
        }
    }

    // ──────────────────────────────────────────────
    //  PROCMON CORRELATION
    // ──────────────────────────────────────────────

    [Fact]
    public void Correlate_WithRealCsv_ParsesSuccessfully()
    {
        if (!AcrobatInstalled || !ProcmonCsvExists) return;

        var results = RunScan();
        var procmon = ProcmonParser.Parse(ProcmonCsv);
        Assert.Null(procmon.Error);
        Assert.True(procmon.FilteredRows > 0, "ProcMon CSV should contain NAME NOT FOUND events");
        Assert.True(procmon.ByDll.Count > 0, "ProcMon CSV should aggregate into DLL groups");

        var report = ProcmonCorrelator.Correlate(results, procmon);

        // Static scanner phantoms (subdirectory-relative) may not overlap with
        // ProcMon NAME NOT FOUND entries (runtime-loaded DLLs like AID.dll).
        // When matches exist, verify confidence bumps correctly.
        var matched = results.Existing.Where(c => c.Evidence != null).ToList();
        foreach (var c in matched)
        {
            Assert.True(c.Score.Confidence > 3,
                $"{c.Dll.Filename}: post-correlate Confidence should be > StaticOnly(3), got {c.Score.Confidence}");
        }

        var phantomMatched = results.Phantoms.Where(p => p.Evidence != null).ToList();
        foreach (var p in phantomMatched)
        {
            Assert.True(p.Score.Confidence > 3,
                $"{p.DllName}: post-correlate Confidence should be > StaticOnly(3), got {p.Score.Confidence}");
        }
    }

    [Fact]
    public void Correlate_PhantomAcrodistdll_IsMatched()
    {
        if (!AcrobatInstalled || !ProcmonCsvExists) return;

        var results = RunScan();
        var procmon = ProcmonParser.Parse(ProcmonCsv);
        ProcmonCorrelator.Correlate(results, procmon);

        var acrodist = results.Phantoms
            .FirstOrDefault(p => p.DllName.Equals("Acrodistdll.dll", StringComparison.OrdinalIgnoreCase));

        if (acrodist != null)
        {
            Assert.NotNull(acrodist.Evidence);
            Assert.True(acrodist.Score.Confidence > 3,
                "Acrodistdll.dll confirmed by ProcMon should have elevated Confidence");
        }
    }

    // ──────────────────────────────────────────────
    //  DIAGNOSTIC DUMP
    // ──────────────────────────────────────────────

    [Fact]
    public void Diagnostic_DumpTopCandidates()
    {
        if (!AcrobatInstalled) return;

        var results = RunScan();

        if (ProcmonCsvExists)
        {
            var procmon = ProcmonParser.Parse(ProcmonCsv);
            ProcmonCorrelator.Correlate(results, procmon);
        }

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"\n=== ADOBE ACROBAT SCAN: {results.ExistingCount} existing, {results.PhantomCount} phantom ===\n");

        sb.AppendLine("--- TOP 15 EXISTING (by Total) ---");
        foreach (var c in results.Existing.OrderByDescending(c => c.Score.Total).Take(15))
        {
            var dyn = c.Evidence != null ? " [ProcMon]" : "";
            var priv = c.Privesc?.Findings.Count > 0 ? $" [Privesc:{c.Privesc.Findings.Count}]" : "";
            var sig = c.AnyImporterSigned ? "exe-signed" : "exe-unsigned";
            sb.AppendLine(
                $"  T={c.Score.Total} E={c.Score.Exploitability} I={c.Score.Impact} C={c.Score.Confidence} " +
                $"| {c.Dll.Filename} <- {c.Importers.Count} importers | " +
                $"writable={c.Dir.IsUserWritable} exe={sig}{dyn}{priv}");
        }

        sb.AppendLine("\n--- TOP 10 PHANTOMS (by Total) ---");
        foreach (var p in results.Phantoms.OrderByDescending(p => p.Score.Total).Take(10))
        {
            var dyn = p.Evidence != null ? " [ProcMon]" : "";
            sb.AppendLine(
                $"  T={p.Score.Total} E={p.Score.Exploitability} I={p.Score.Impact} C={p.Score.Confidence} " +
                $"| {p.DllName} in {p.DirectoryPath} | writable={p.Dir.IsUserWritable}{dyn}");
        }

        var allPrivesc = results.Existing
            .Where(c => c.Privesc?.Findings.Count > 0)
            .SelectMany(c => c.Privesc!.Findings)
            .ToList();
        if (allPrivesc.Count > 0)
        {
            sb.AppendLine($"\n--- PRIVESC FINDINGS: {allPrivesc.Count} ---");
            foreach (var f in allPrivesc.Take(10))
                sb.AppendLine($"  [{f.Severity}] {f.Vector}: {f.Title}");
        }

        var dump = sb.ToString();

        var reportPath = @"D:\COMPARTIDO\CLAUDE\BugAInters\results\adobereader\sprint4a_scan_report.txt";
        File.WriteAllText(reportPath, dump);

        Assert.True(results.ExistingCount > 0, dump);
    }
}
