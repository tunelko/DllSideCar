using Microsoft.Win32;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Execution;
using DllSidecar.Core.Models.Privesc;
using DllSidecar.Core.Services.Execution;

namespace DllSidecar.Core.Services.Privesc;

/// <summary>
/// Detects PEs loaded by Windows services. Reads HKLM\SYSTEM\CurrentControlSet\Services
/// directly — no elevation required for read.
///
/// Sprint-2 robustness: ImagePath is parsed through <see cref="ExecutionResolver"/>, so
/// quoted paths with spaces, embedded arguments, env vars, and cmd/powershell/rundll32/msiexec
/// wrappers are all recognised (one level of wrapping). ServiceDll is resolved the same
/// way so svchost-hosted services reach findings via a uniform code path.
///
/// Match severity:
///   - LocalSystem / NT AUTHORITY\SYSTEM = High (user → SYSTEM)
///   - LocalService / NetworkService     = Medium
///   - user-specific account             = Informational
/// </summary>
public class ServicesDetector : IPrivescDetector
{
    public string Name => "ServicesDetector";

    // Lowercased PE path → list of services that load it
    private readonly Dictionary<string, List<ServiceEntry>> _peToServices =
        new(StringComparer.OrdinalIgnoreCase);

    public enum ServiceSource
    {
        ImagePath,  // Main service binary (EXE)
        ServiceDll, // svchost group — the DLL loaded into svchost.exe
    }

    public class ServiceEntry
    {
        public required string Name { get; set; }
        public required string ResolvedPath { get; set; }
        public required string ObjectName { get; set; }
        public required ServiceSource Source { get; set; }
        public string OriginalCommand { get; set; } = "";
        public string? Arguments { get; set; }
        public WrapperKind Wrapper { get; set; } = WrapperKind.None;
        public ResolutionStatus ResolutionStatus { get; set; } = ResolutionStatus.Resolved;
        public int StartType { get; set; } // 0=boot, 1=system, 2=auto, 3=manual, 4=disabled

        public bool ResolvedViaWrapper => Wrapper != WrapperKind.None;

        public bool RunsAsSystem =>
            string.IsNullOrEmpty(ObjectName) ||
            ObjectName.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase) ||
            ObjectName.Equals(".\\LocalSystem", StringComparison.OrdinalIgnoreCase) ||
            ObjectName.Equals("NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase);

        public bool RunsAsRestrictedService =>
            ObjectName.Equals("NT AUTHORITY\\LocalService", StringComparison.OrdinalIgnoreCase) ||
            ObjectName.Equals("NT AUTHORITY\\NetworkService", StringComparison.OrdinalIgnoreCase);
    }

    public void Prepare(PrivescDetectorContext ctx, CancellationToken ct)
    {
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (servicesKey == null)
            {
                Log.Warn("privesc.services", "Could not open HKLM\\SYSTEM\\CurrentControlSet\\Services");
                return;
            }

            int totalServices = 0, matched = 0;
            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                totalServices++;

                try
                {
                    using var svc = servicesKey.OpenSubKey(svcName);
                    if (svc == null) continue;

                    var imagePath = svc.GetValue("ImagePath") as string;
                    var objectName = svc.GetValue("ObjectName") as string ?? "LocalSystem";
                    var startType = (svc.GetValue("Start") as int?) ?? 3;

                    using var parameters = svc.OpenSubKey("Parameters");
                    var serviceDll = parameters?.GetValue("ServiceDll") as string;

                    var entries = BuildEntries(svcName, imagePath, serviceDll, objectName, startType);
                    foreach (var e in entries)
                    {
                        if (TryMatchScanned(e.ResolvedPath, ctx, out var matchKey))
                        {
                            // Re-key match on original PE.Path (case-preserving) for dictionary lookup
                            e.ResolvedPath = matchKey;
                            AddMatch(matchKey, e);
                            matched++;
                        }
                    }
                }
                catch (System.Security.SecurityException) { /* read denied on specific service */ }
                catch (Exception ex)
                {
                    Log.Debug("privesc.services", $"Error reading service {svcName}", ex);
                }
            }

            Log.Info("privesc.services",
                $"Enumerated {totalServices} services; {matched} match scanned PEs ({_peToServices.Count} unique bins)");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            Log.Error("privesc.services", "Services enumeration failed", ex);
        }
    }

    public IEnumerable<PrivescFinding> Detect(PeAnalysis pe, PrivescDetectorContext ctx, CancellationToken ct)
    {
        if (!_peToServices.TryGetValue(pe.Path, out var services)) yield break;

        foreach (var svc in services)
        {
            var severity = svc.RunsAsSystem
                ? PrivescSeverity.High
                : svc.RunsAsRestrictedService
                    ? PrivescSeverity.Medium
                    : PrivescSeverity.Informational;

            var finding = new PrivescFinding
            {
                Vector = PrivescVector.ServiceSystem,
                Severity = severity,
                DetectorName = Name,
                Title = BuildTitle(svc),
                Evidence = BuildEvidence(svc),
                PrivilegedProcessPath = svc.ResolvedPath,
                PrivilegedAccount = svc.ObjectName,
                Extras =
                {
                    ["ServiceName"]        = svc.Name,
                    ["StartType"]          = StartTypeName(svc.StartType),
                    ["ObjectName"]         = svc.ObjectName,
                    ["Source"]             = svc.Source.ToString(),
                    ["IsSvchostDll"]       = (svc.Source == ServiceSource.ServiceDll).ToString(),
                    ["OriginalCommand"]    = svc.OriginalCommand,
                    ["ResolvedTarget"]     = svc.ResolvedPath,
                    ["ResolvedViaWrapper"] = svc.ResolvedViaWrapper ? "true" : "false",
                    ["WrapperKind"]        = svc.Wrapper.ToString(),
                    ["ResolutionStatus"]   = svc.ResolutionStatus.ToString(),
                },
            };
            if (!string.IsNullOrEmpty(svc.Arguments))
                finding.Extras["Arguments"] = svc.Arguments;

            yield return finding;
        }
    }

    /// <summary>
    /// Build candidate ServiceEntry rows from raw registry values. Pure — no I/O.
    /// Exposed for unit tests. Returns both the ImagePath entry and the ServiceDll entry
    /// when present; callers filter by whether the path actually matches a scanned PE.
    /// </summary>
    public static List<ServiceEntry> BuildEntries(
        string serviceName,
        string? imagePath,
        string? serviceDll,
        string? objectName,
        int startType)
    {
        var entries = new List<ServiceEntry>();
        var account = string.IsNullOrWhiteSpace(objectName) ? "LocalSystem" : objectName;

        // ImagePath — may contain quotes, args, or wrappers
        if (!string.IsNullOrWhiteSpace(imagePath))
        {
            var resolved = ExecutionResolver.Resolve(imagePath);
            if (!string.IsNullOrEmpty(resolved.ResolvedPath))
            {
                entries.Add(new ServiceEntry
                {
                    Name = serviceName,
                    ResolvedPath = resolved.ResolvedPath,
                    ObjectName = account,
                    Source = ServiceSource.ImagePath,
                    OriginalCommand = resolved.OriginalCommand,
                    Arguments = resolved.Arguments,
                    Wrapper = resolved.Wrapper,
                    ResolutionStatus = resolved.Status,
                    StartType = startType,
                });
            }
        }

        // ServiceDll — a bare module path (REG_EXPAND_SZ). Never has arguments — svchost
        // loads it via LoadLibrary. Skip the tokenizer so paths with spaces aren't split.
        if (!string.IsNullOrWhiteSpace(serviceDll))
        {
            var expanded = ExpandEnvSafe(serviceDll).Trim().Trim('"');
            if (!string.IsNullOrEmpty(expanded))
            {
                entries.Add(new ServiceEntry
                {
                    Name = serviceName,
                    ResolvedPath = expanded,
                    ObjectName = account,
                    Source = ServiceSource.ServiceDll,
                    OriginalCommand = serviceDll,
                    Wrapper = WrapperKind.None,
                    ResolutionStatus = ResolutionStatus.Resolved,
                    StartType = startType,
                });
            }
        }

        return entries;
    }

    private void AddMatch(string path, ServiceEntry entry)
    {
        if (!_peToServices.TryGetValue(path, out var list))
        {
            list = [];
            _peToServices[path] = list;
        }
        list.Add(entry);
    }

    private static bool TryMatchScanned(string path, PrivescDetectorContext ctx, out string matchKey)
    {
        matchKey = "";
        try
        {
            var normalized = Path.GetFullPath(path).ToLowerInvariant();
            if (ctx.AllScannedPaths.Contains(normalized))
            {
                matchKey = ctx.PathToPe[normalized].Path;
                return true;
            }
        }
        catch (ArgumentException) { /* bad chars in path — skip */ }
        catch (NotSupportedException) { /* likewise */ }
        return false;
    }

    private static string BuildTitle(ServiceEntry svc)
    {
        if (svc.Source == ServiceSource.ServiceDll)
            return $"Loaded by svchost service '{svc.Name}' via ServiceDll";
        if (svc.ResolvedViaWrapper)
            return $"Main binary of service '{svc.Name}' via {svc.Wrapper.ToString().ToLowerInvariant()}";
        return $"Main binary of service '{svc.Name}'";
    }

    private static string BuildEvidence(ServiceEntry svc)
    {
        var root = $"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc.Name}";
        var parts = new List<string>
        {
            svc.Source == ServiceSource.ServiceDll
                ? $"{root}\\Parameters\\ServiceDll = {svc.ResolvedPath}"
                : $"{root}\\ImagePath = {svc.OriginalCommand}",
            $"StartType: {StartTypeName(svc.StartType)}",
            $"ObjectName: {svc.ObjectName}",
        };
        if (svc.ResolvedViaWrapper)
            parts.Add($"Wrapper: {svc.Wrapper} → {svc.ResolvedPath}");
        return string.Join("  ·  ", parts);
    }

    private static string ExpandEnvSafe(string s)
    {
        try { return Environment.ExpandEnvironmentVariables(s); }
        catch { return s; }
    }

    private static string StartTypeName(int t) => t switch
    {
        0 => "boot", 1 => "system", 2 => "auto", 3 => "manual", 4 => "disabled",
        _ => $"unknown({t})",
    };
}
