using DllSidecar.Core.Helpers;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>Minimal evidence shape for both ProcMon CSV and live ETW pipelines.</summary>
public sealed record CarrierInput(
    string DllName,
    bool IsHighIlSearch,
    IReadOnlyList<string> SearchedDirs,
    int LoaderLikeCount,
    int MetadataProbeCount,
    int EventCount);

/// <summary>Identified carrier DLL with its plant slot (first user-writable dir).</summary>
public sealed record PrivescCarrier(
    string DllName,
    int EventCount,
    string PlantSlot);

/// <summary>Carrier filter. Gates: HighIL search, not KnownDLL, at least one user-writable search dir.</summary>
public static class PrivescCarrierIdentifier
{
    /// <summary>
    /// Filter and rank carriers; inputs sharing a <c>DllName</c> are merged. Returned sorted by event count descending.
    /// </summary>
    public static List<PrivescCarrier> Identify(IEnumerable<CarrierInput> inputs, DirAclCache acl)
    {
        var byName = new Dictionary<string, (int Events, string Slot)>(StringComparer.OrdinalIgnoreCase);

        foreach (var input in inputs)
        {
            if (!Qualifies(input, acl, out var plantSlot)) continue;

            if (byName.TryGetValue(input.DllName, out var existing))
                byName[input.DllName] = (existing.Events + input.EventCount, existing.Slot);
            else
                byName[input.DllName] = (input.EventCount, plantSlot);
        }

        return byName
            .Select(kv => new PrivescCarrier(kv.Key, kv.Value.Events, kv.Value.Slot))
            .OrderByDescending(c => c.EventCount)
            .ToList();
    }

    /// <summary>
    /// Single-row predicate so per-row verdicts and the banner stay in lockstep.
    /// </summary>
    public static bool Qualifies(CarrierInput input, DirAclCache acl, out string plantSlot)
    {
        plantSlot = "";

        if (!input.IsHighIlSearch) return false;
        if (KnownDlls.IsKnown(input.DllName)) return false;

        foreach (var dir in input.SearchedDirs)
        {
            var perms = acl.Get(dir);
            if (string.IsNullOrEmpty(perms.Error) && perms.IsUserWritable)
            {
                plantSlot = dir;
                break;
            }
        }
        if (string.IsNullOrEmpty(plantSlot)) return false;
        return true;
    }

    /// <summary>CSV pipeline overload: projects <see cref="ProcmonAggregation"/> into <see cref="CarrierInput"/>.</summary>
    public static List<PrivescCarrier> FromAggregations(
        IEnumerable<ProcmonAggregation> aggregations, DirAclCache acl)
    {
        return Identify(aggregations.Select(a => new CarrierInput(
            DllName: a.DllName,
            IsHighIlSearch: a.HighIlSearch,
            SearchedDirs: a.SearchedDirs.ToList(),
            LoaderLikeCount: a.LoaderLikeCount,
            MetadataProbeCount: a.MetadataProbeCount,
            EventCount: a.EventCount)), acl);
    }
}
