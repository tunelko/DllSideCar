using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace DllSidecar.GUI.Views;

/// <summary>Modal to pick a running process by PID; returns via <see cref="SelectedPid"/> when DialogResult=true.</summary>
public partial class ProcessPickerDialog : Window
{
    private readonly Dictionary<int, ProcInfo> _allByPid = new();
    private readonly int _currentSession;

    public int? SelectedPid { get; private set; }
    public string? SelectedName { get; private set; }

    public ProcessPickerDialog()
    {
        InitializeComponent();
        Services.WindowChromeHelper.Apply(this, "Attach to process — pick a running PID");
        _currentSession = Process.GetCurrentProcess().SessionId;
        Loaded += (_, _) => Load();
    }

    // ---------- Load ----------

    private void Load()
    {
        _allByPid.Clear();
        var parentMap = SnapshotParentMap();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                _allByPid[p.Id] = new ProcInfo
                {
                    Pid = p.Id,
                    ParentPid = parentMap.TryGetValue(p.Id, out var pp) ? pp : 0,
                    Name = p.ProcessName,
                    Title = SafeMainWindowTitle(p),
                    Session = p.SessionId,
                    HasWindow = p.MainWindowHandle != IntPtr.Zero,
                };
            }
            catch { /* exited / access denied */ }
            finally { p.Dispose(); }
        }
        ApplyFilter();
    }

    private static string SafeMainWindowTitle(Process p)
    {
        try { return p.MainWindowTitle ?? ""; }
        catch { return ""; }
    }

    // ---------- Filter + tree build ----------

    private void ApplyFilter()
    {
        // Checked="True" can fire before sibling controls exist.
        if (Tree == null || FilterBox == null || Status == null) return;

        var q = FilterBox.Text.Trim();
        var onlyWin = ChkWithWindow.IsChecked == true;
        var onlySess = ChkCurrentSession.IsChecked == true;

        bool MatchesSelf(ProcInfo p)
        {
            if (onlyWin && !p.HasWindow) return false;
            if (onlySess && p.Session != _currentSession) return false;
            if (q.Length == 0) return true;
            return p.Name.Contains(q, StringComparison.OrdinalIgnoreCase)
                || p.Title.Contains(q, StringComparison.OrdinalIgnoreCase)
                || p.Pid.ToString().Contains(q);
        }

        // Build children index (parent PID → list of child ProcInfo)
        var childrenByParent = new Dictionary<int, List<ProcInfo>>();
        foreach (var p in _allByPid.Values)
        {
            if (!childrenByParent.TryGetValue(p.ParentPid, out var list))
                childrenByParent[p.ParentPid] = list = new List<ProcInfo>();
            list.Add(p);
        }

        // Keep a node if it matches or any descendant does (ancestors stay for context).
        ProcNode? Build(ProcInfo p, HashSet<int> visited)
        {
            if (!visited.Add(p.Pid)) return null; // cycle guard
            var node = new ProcNode { Info = p };
            if (childrenByParent.TryGetValue(p.Pid, out var kids))
            {
                foreach (var k in kids.OrderBy(c => c.Name, StringComparer.OrdinalIgnoreCase))
                {
                    var cn = Build(k, visited);
                    if (cn != null) node.Children.Add(cn);
                }
            }
            return (MatchesSelf(p) || node.Children.Count > 0) ? node : null;
        }

        // Roots: parent missing from snapshot or self-referential.
        var rootInfos = _allByPid.Values
            .Where(p => p.ParentPid == 0 || !_allByPid.ContainsKey(p.ParentPid) || p.ParentPid == p.Pid)
            .OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var visited = new HashSet<int>();
        var result = new List<ProcNode>();
        foreach (var r in rootInfos)
        {
            var n = Build(r, visited);
            if (n != null) result.Add(n);
        }

        Tree.ItemsSource = null;
        Tree.ItemsSource = result;
        var visibleCount = CountAll(result);
        var matchingCount = CountMatching(result, MatchesSelf);
        Status.Text = q.Length == 0 && !onlyWin && !onlySess
            ? $"{_allByPid.Count} processes"
            : $"{matchingCount} matching · {visibleCount} visible (incl. ancestors) · {_allByPid.Count} total";
    }

    private static int CountAll(IEnumerable<ProcNode> nodes)
    {
        int n = 0;
        foreach (var x in nodes) { n++; n += CountAll(x.Children); }
        return n;
    }

    private static int CountMatching(IEnumerable<ProcNode> nodes, Func<ProcInfo, bool> match)
    {
        int n = 0;
        foreach (var x in nodes)
        {
            if (match(x.Info)) n++;
            n += CountMatching(x.Children, match);
        }
        return n;
    }

    // ---------- Event handlers ----------

    private void Filter_Changed(object sender, RoutedEventArgs e) => ApplyFilter();
    private void Filter_Changed(object sender, TextChangedEventArgs e) => ApplyFilter();
    private void Refresh_Click(object sender, RoutedEventArgs e) => Load();

    private void Tree_SelectedChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is ProcNode n)
        {
            SelectedPid = n.Info.Pid;
            SelectedName = n.Info.Name;
            OkBtn.IsEnabled = true;
        }
        else
        {
            SelectedPid = null;
            SelectedName = null;
            OkBtn.IsEnabled = false;
        }
    }

    private void Tree_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (Tree.SelectedItem is ProcNode) Accept();
    }

    private void Ok_Click(object sender, RoutedEventArgs e) => Accept();
    private void Cancel_Click(object sender, RoutedEventArgs e) { DialogResult = false; Close(); }

    private void Accept()
    {
        if (Tree.SelectedItem is not ProcNode) return;
        DialogResult = true;
        Close();
    }

    // ---------- Toolhelp PInvoke for parent PID lookup ----------

    private static Dictionary<int, int> SnapshotParentMap()
    {
        var map = new Dictionary<int, int>();
        var snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == IntPtr.Zero || snap == InvalidHandleValue) return map;
        try
        {
            var pe = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
            if (!Process32FirstW(snap, ref pe)) return map;
            do { map[(int)pe.th32ProcessID] = (int)pe.th32ParentProcessID; }
            while (Process32NextW(snap, ref pe));
        }
        finally { CloseHandle(snap); }
        return map;
    }

    private const uint TH32CS_SNAPPROCESS = 0x00000002;
    private static readonly IntPtr InvalidHandleValue = new(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    // ---------- View models ----------

    private class ProcInfo
    {
        public int Pid { get; init; }
        public int ParentPid { get; init; }
        public string Name { get; init; } = "";
        public string Title { get; init; } = "";
        public int Session { get; init; }
        public bool HasWindow { get; init; }
    }

    private class ProcNode
    {
        public ProcInfo Info { get; init; } = null!;
        public List<ProcNode> Children { get; } = [];
    }
}
