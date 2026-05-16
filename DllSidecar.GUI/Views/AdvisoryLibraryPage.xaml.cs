using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.IO.Compression;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using DllSidecar.Core.Models.AdvisoryLibrary;
using DllSidecar.Core.Services.AdvisoryLibrary;
using DllSidecar.Core.Services.Advisory.Rendering;

namespace DllSidecar.GUI.Views;

public partial class AdvisoryLibraryPage : Page
{
    private readonly MainWindow _main;
    private readonly AdvisoryRepository _repo = new();
    private readonly List<RecordRow> _rows = [];
    private AdvisoryRecord? _loaded;

    public AdvisoryLibraryPage(MainWindow main)
    {
        _main = main;
        InitializeComponent();
        Loaded += async (_, _) => await InitAndLoadAsync();
    }

    private async Task InitAndLoadAsync()
    {
        try
        {
            await _repo.InitializeAsync();
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            SetStatus($"Library init failed: {ex.Message}", StatusKind.Err);
            _main.Log($"AdvisoryLibrary init error: {ex.Message}");
        }
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    // Root of the tree bound to RecordsTree. Rebuilt every RefreshAsync. Holds a heterogeneous
    // list of VendorNode (regular vendors) followed by a single TrashNode at the end.
    private readonly ObservableCollection<object> _roots = [];
    private readonly TrashNode _trash = new();

    private async Task RefreshAsync()
    {
        try
        {
            var q = BuildQuery();
            var items = await _repo.ListAsync(q);

            _rows.Clear();
            foreach (var it in items) _rows.Add(new RecordRow(it));

            // Fetch the artifact index once so we can fold files into format folders without
            // per-advisory round-trips.
            var artifactsByAdvisory = await _repo.GetArtifactsIndexAsync();
            var deleted = await _repo.ListDeletedAsync();

            // Flat hierarchy: Vendor → FileLeafNode. The previous Vendor → FormatFolder →
            // File grouping was dropped — the filename itself (DLL_SIDELOADING_ADVISORY_NNNN
            // .md/.txt/.yaml) already conveys which renderer produced it, so the extra
            // folder level was navigational tax without information. Files sort by filename
            // so all artifacts of one advisory cluster naturally (0001.md / 0001.txt /
            // 0001.yaml / 0002.md ...) thanks to the sequence-padded filename convention.
            //
            // For the Trash group we keep one AdvisoryNode per deleted record because
            // Restore acts on the whole advisory (not on a single file), so the user needs
            // a parent handle to drag back to the vendor tree.
            AdvisoryNode BuildTrashNode(AdvisoryRecordListItem it)
            {
                var adv = new AdvisoryNode(it);
                if (artifactsByAdvisory.TryGetValue(it.Id, out var arts) && arts != null)
                {
                    foreach (var a in arts.OrderBy(x => x.Path, StringComparer.OrdinalIgnoreCase))
                        adv.Files.Add(new FileLeafNode(a));
                }
                return adv;
            }

            _roots.Clear();
            foreach (var group in items
                .GroupBy(i => string.IsNullOrWhiteSpace(i.Vendor) ? "(no vendor)" : i.Vendor!)
                .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
            {
                var vendor = new VendorNode { Name = group.Key };
                var sortedAdvisories = group.OrderByDescending(i => i.UpdatedAtUtc).ToList();
                vendor.Advisories.AddRange(sortedAdvisories);

                foreach (var it in sortedAdvisories)
                {
                    if (!artifactsByAdvisory.TryGetValue(it.Id, out var arts) || arts == null) continue;
                    foreach (var a in arts.OrderBy(x => x.Path, StringComparer.OrdinalIgnoreCase))
                        vendor.Files.Add(new FileLeafNode(a, it));
                }
                _roots.Add(vendor);
            }

            _trash.Advisories.Clear();
            foreach (var it in deleted) _trash.Advisories.Add(BuildTrashNode(it));
            _roots.Add(_trash);
            RecordsTree.ItemsSource = _roots;

            if (_rows.Count == 0)
                SetStatus("Library empty — save your first advisory from the AdvisoryPage.", StatusKind.Info);
            else
                SetStatus($"{_rows.Count} advisories across {_roots.OfType<VendorNode>().Count()} vendors · latest update {_rows[0].UpdatedText}", StatusKind.Ok);
        }
        catch (Exception ex)
        {
            SetStatus($"Refresh failed: {ex.Message}", StatusKind.Err);
        }
    }

    private AdvisoryQuery BuildQuery()
    {
        var q = new AdvisoryQuery { Search = SearchBox.Text?.Trim() };
        if (StatusFilterCombo.SelectedIndex > 0
            && StatusFilterCombo.SelectedItem is ComboBoxItem item
            && item.Content is string s
            && Enum.TryParse<AdvisoryStatus>(s, out var st))
        {
            q.Status = st;
        }
        return q;
    }

    private async void Search_Changed(object sender, TextChangedEventArgs e)
    {
        if (!IsLoaded) return;
        await RefreshAsync();
    }

    private async void StatusFilter_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        await RefreshAsync();
    }

    // True when the selected advisory is currently inside the Trash group. Toggles the
    // action icons between normal (open/status/note/delete) and trash (restore/permanent).
    private bool _selectedIsTrashed;
    private VendorNode? _selectedVendor;

    private async void RecordsTree_SelectionChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        _selectedIsTrashed = IsUnderTrash(e.NewValue);
        _selectedVendor = null;
        switch (e.NewValue)
        {
            case AdvisoryNode adv:
                _loaded = await _repo.GetAsync(adv.Item.Id);
                _selectedLeaf = null;
                if (_loaded != null) RenderDetails(_loaded);
                UpdateAdvisoryActionIcons();
                ShowPane(Pane.Advisory);
                break;

            case FileLeafNode leaf:
                _selectedLeaf = leaf;
                if (leaf.Owner != null && !_selectedIsTrashed)
                {
                    // Main tree: a file leaf is the user's primary handle on its parent advisory.
                    // Load the record and show the Advisory pane so the action icons (Open in
                    // AdvisoryPage ↗, Status ⇄, Note ✎, Export 📦, Delete 🗑) all apply to the
                    // owning record. File preview pane is reserved for Trash leaves where there
                    // is no editable owner to act on.
                    _loaded = await _repo.GetAsync(leaf.Owner.Id);
                    if (_loaded != null) RenderDetails(_loaded);
                    UpdateAdvisoryActionIcons();
                    ShowPane(Pane.Advisory);
                }
                else
                {
                    RenderFilePreview(leaf);
                    ShowPane(Pane.File);
                }
                break;

            case TrashNode trash:
                _loaded = null;
                _selectedLeaf = null;
                RenderTrashSummary(trash);
                ShowPane(Pane.Trash);
                break;

            case VendorNode vendor:
                _loaded = null;
                _selectedLeaf = null;
                _selectedVendor = vendor;
                RenderVendorSummary(vendor);
                ShowPane(Pane.Vendor);
                break;

            default:
                _loaded = null;
                _selectedLeaf = null;
                ShowPane(Pane.Empty);
                break;
        }
    }

    /// <summary>Returns true if the given node is the TrashNode or a descendant of it.</summary>
    private bool IsUnderTrash(object? node) => node switch
    {
        TrashNode => true,
        AdvisoryNode adv => _trash.Advisories.Contains(adv),
        FileLeafNode leaf => _trash.Advisories.Any(a => a.Files.Contains(leaf)),
        _ => false,
    };

    // ---- Vendor rename (double-click) --------------------------------------

    /// <summary>
    /// Double-click on a vendor row → enter edit mode. Also swallows the event so the
    /// TreeViewItem's default double-click handler doesn't toggle expansion.
    /// </summary>
    private void Vendor_MouseDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (e.ClickCount != 2) return;
        if (sender is not FrameworkElement fe || fe.DataContext is not VendorNode vendor) return;
        if (vendor.Name == "(no vendor)") vendor.OriginalName = "";
        else vendor.OriginalName = vendor.Name;
        vendor.IsEditing = true;
        e.Handled = true; // stop WPF from expanding/collapsing the parent TreeViewItem
    }

    private void VendorEdit_Loaded(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.TextBox tb)
        {
            tb.Focus();
            tb.SelectAll();
        }
    }

    private async void VendorEdit_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (sender is not System.Windows.Controls.TextBox tb || tb.DataContext is not VendorNode vendor) return;
        if (e.Key == System.Windows.Input.Key.Enter)
        {
            e.Handled = true;
            await CommitVendorRenameAsync(vendor);
        }
        else if (e.Key == System.Windows.Input.Key.Escape)
        {
            e.Handled = true;
            vendor.Name = string.IsNullOrEmpty(vendor.OriginalName) ? "(no vendor)" : vendor.OriginalName;
            vendor.IsEditing = false;
        }
    }

    private async void VendorEdit_LostFocus(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.TextBox tb && tb.DataContext is VendorNode vendor && vendor.IsEditing)
            await CommitVendorRenameAsync(vendor);
    }

    private async Task CommitVendorRenameAsync(VendorNode vendor)
    {
        // Guard against double-commit: Enter fires commit → RefreshAsync rebuilds the tree →
        // the old TextBox is destroyed → LostKeyboardFocus on the now-orphan vendor fires a
        // second commit. Without this flip, the second commit issues UPDATE WHERE vendor=old
        // against a DB where 0 records still match, reporting "0 record(s) re-grouped" and
        // making the user think the rename failed.
        if (!vendor.IsEditing) return;
        vendor.IsEditing = false;

        var newName = vendor.Name?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(newName) || newName == vendor.OriginalName) return;
        try
        {
            var n = await _repo.RenameVendorAsync(vendor.OriginalName, newName);
            _main.Log($"Vendor rename: '{vendor.OriginalName}' ({vendor.Count} in group) → '{newName}' — {n} record(s) updated");
            // Update OriginalName so any delayed second commit on the same in-memory object
            // short-circuits via the newName == OriginalName check above.
            vendor.OriginalName = newName;
            SetStatus($"Vendor updated — {n} record(s) re-grouped as '{newName}'.", StatusKind.Ok);
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            SetStatus($"Rename failed: {ex.Message}", StatusKind.Err);
            vendor.Name = vendor.OriginalName;
        }
    }

    private enum Pane { Empty, Advisory, File, Vendor, Trash }

    private FileLeafNode? _selectedLeaf;

    private void ShowPane(Pane p)
    {
        DetailEmpty.Visibility    = p == Pane.Empty    ? Visibility.Visible : Visibility.Collapsed;
        DetailContent.Visibility  = p == Pane.Advisory ? Visibility.Visible : Visibility.Collapsed;
        ActionIconsBar.Visibility = p == Pane.Advisory ? Visibility.Visible : Visibility.Collapsed;
        FilePreviewPanel.Visibility = p == Pane.File   ? Visibility.Visible : Visibility.Collapsed;
        VendorPanel.Visibility      = p == Pane.Vendor ? Visibility.Visible : Visibility.Collapsed;
        TrashPanel.Visibility       = p == Pane.Trash  ? Visibility.Visible : Visibility.Collapsed;

        // The header ⛶ only helps when there's actually a rich, scrollable body worth expanding
        // (advisory details + file preview). Vendor / Trash / Empty show compact summaries
        // that already fit in the pane — expanding them is just extra clicks.
        ExpandAdvisoryBtn.Visibility = (p == Pane.Advisory || p == Pane.File) ? Visibility.Visible : Visibility.Collapsed;
    }

    // ---- Vendor / Trash summary panes ------------------------------------

    private void RenderVendorSummary(VendorNode vendor)
    {
        VendorSummaryTitle.Text = vendor.Name;
        var items = vendor.Advisories;  // already a List<AdvisoryRecordListItem>
        VendorSummaryCount.Text = $"{items.Count} advisory·ies";

        // Severity breakdown — CVSS v3 score buckets
        var crit = items.Count(i => BucketForVendorRow(i) == "CRITICAL");
        var high = items.Count(i => BucketForVendorRow(i) == "HIGH");
        var med  = items.Count(i => BucketForVendorRow(i) == "MEDIUM");
        var low  = items.Count(i => BucketForVendorRow(i) == "LOW");
        var none = items.Count - crit - high - med - low;
        VendorSeverityText.Text = $"Critical {crit}  ·  High {high}  ·  Medium {med}  ·  Low {low}  ·  Unscored {none}";

        // Status breakdown
        var byStatus = items.GroupBy(i => i.Status).OrderBy(g => (int)g.Key)
            .Select(g => $"{g.Key} {g.Count()}");
        VendorStatusText.Text = string.Join("  ·  ", byStatus);

        VendorAdvisoriesList.ItemsSource = items.Select(i => new VendorSummaryRow(i)).ToList();
    }

    /// <summary>
    /// Map a list-item to a severity bucket for the vendor summary. We don't have CVSS in
    /// the list DTO, so we approximate via Status (e.g. CveAssigned / Public => high signal).
    /// Good enough for a quick glance; the real number lives in the per-advisory detail.
    /// </summary>
    private static string BucketForVendorRow(AdvisoryRecordListItem i) => i.Status switch
    {
        AdvisoryStatus.Public or AdvisoryStatus.CveAssigned => "HIGH",
        AdvisoryStatus.SentToVendor or AdvisoryStatus.Acknowledged or AdvisoryStatus.CveRequested => "MEDIUM",
        AdvisoryStatus.Fixed => "LOW",
        _ => "UNSCORED",
    };

    private void RenderTrashSummary(TrashNode trash)
    {
        TrashSummaryCount.Text = $"{trash.Advisories.Count} deleted advisory·ies";
        TrashAdvisoriesList.ItemsSource = trash.Advisories.Select(a => new VendorSummaryRow(a.Item)).ToList();
    }

    // ---- Vendor-level actions (only Delete-all-soft; expand isn't useful for compact summaries) ----

    private async void DeleteVendor_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedVendor == null) return;
        var count = _selectedVendor.Advisories.Count;
        var r = MessageBox.Show(
            $"Move all {count} advisory·ies under '{_selectedVendor.Name}' to Trash?\n\nThey can be restored later.",
            "Delete vendor group", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (r != MessageBoxResult.Yes) return;
        try
        {
            foreach (var adv in _selectedVendor.Advisories.ToList())
                await _repo.SoftDeleteAsync(adv.Id);
            await RefreshAsync();
            ShowPane(Pane.Empty);
        }
        catch (Exception ex) { SetStatus($"Bulk delete failed: {ex.Message}", StatusKind.Err); }
    }

    // ---- Action icons for advisory: swap between normal set and trash set ----

    private void UpdateAdvisoryActionIcons()
    {
        NormalActions.Visibility = _selectedIsTrashed ? Visibility.Collapsed : Visibility.Visible;
        TrashActions.Visibility  = _selectedIsTrashed ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void RestoreAdvisory_Click(object sender, RoutedEventArgs e)
    {
        if (_loaded == null) return;
        try
        {
            await _repo.RestoreAsync(_loaded.Id);
            _main.Log($"Advisory {_loaded.Id} restored from trash");
            await RefreshAsync();
        }
        catch (Exception ex) { SetStatus($"Restore failed: {ex.Message}", StatusKind.Err); }
    }

    private async void PermanentDelete_Click(object sender, RoutedEventArgs e)
    {
        if (_loaded == null) return;
        var r = MessageBox.Show(
            $"Permanently delete '{_loaded.Title}'?\n\nTimeline, artifacts and linked files will all be removed from disk. This cannot be undone.",
            "Permanent delete", MessageBoxButton.YesNo, MessageBoxImage.Stop);
        if (r != MessageBoxResult.Yes) return;
        try
        {
            await _repo.PermanentDeleteAsync(_loaded.Id);
            _main.Log($"Advisory {_loaded.Id} permanently deleted");
            _loaded = null;
            ShowPane(Pane.Empty);
            await RefreshAsync();
        }
        catch (Exception ex) { SetStatus($"Permanent delete failed: {ex.Message}", StatusKind.Err); }
    }

    // ---- Export / Import ------------------------------------------------

    /// <summary>
    /// Export every advisory under the currently selected vendor as a single ZIP containing
    /// one <c>.dsa</c> per advisory. Reuses the single-advisory bundle machinery — no new
    /// multi-advisory format required; the outer ZIP is just a transport wrapper.
    /// </summary>
    private async void ExportVendorBundle_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedVendor == null || _selectedVendor.Advisories.Count == 0) return;
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "ZIP of .dsa bundles|*.zip",
            FileName = $"{SanitizeFilename(_selectedVendor.Name)}-library-{DateTime.Now:yyyyMMdd}.zip",
            DefaultExt = ".zip",
        };
        if (dlg.ShowDialog() != true) return;

        var tempDir = Path.Combine(Path.GetTempPath(), $"dllsidecar-export-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var svc = new AdvisoryBundleService(_repo);
            var inner = new List<string>();
            foreach (var record in _selectedVendor.Advisories)
            {
                var name = $"{SanitizeFilename(record.Title)}-{record.Id}.dsa";
                var path = Path.Combine(tempDir, name);
                await svc.ExportAsync(record.Id, path);
                inner.Add(path);
            }
            if (File.Exists(dlg.FileName)) File.Delete(dlg.FileName);
            using (var outer = System.IO.Compression.ZipFile.Open(dlg.FileName, System.IO.Compression.ZipArchiveMode.Create))
            {
                foreach (var p in inner)
                    outer.CreateEntryFromFile(p, Path.GetFileName(p), System.IO.Compression.CompressionLevel.Optimal);
            }
            SetStatus($"Exported {inner.Count} advisory·ies → {Path.GetFileName(dlg.FileName)}", StatusKind.Ok);
            _main.Log($"Vendor '{_selectedVendor.Name}' exported ({inner.Count} bundles) to {dlg.FileName}");
        }
        catch (Exception ex) { SetStatus($"Vendor export failed: {ex.Message}", StatusKind.Err); }
        finally
        {
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    private async void ExportBundle_Click(object sender, RoutedEventArgs e)
    {
        if (_loaded == null) return;
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "DllSidecar Advisory Bundle (*.dsa)|*.dsa|ZIP file (*.zip)|*.zip",
            FileName = $"{SanitizeFilename(_loaded.Vendor ?? "advisory")}-{SanitizeFilename(_loaded.PeFilename ?? _loaded.Id)}.dsa",
            DefaultExt = ".dsa",
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            var svc = new AdvisoryBundleService(_repo);
            await svc.ExportAsync(_loaded.Id, dlg.FileName);
            SetStatus($"Exported → {Path.GetFileName(dlg.FileName)}", StatusKind.Ok);
            _main.Log($"Advisory {_loaded.Id} exported to {dlg.FileName}");
        }
        catch (Exception ex) { SetStatus($"Export failed: {ex.Message}", StatusKind.Err); }
    }

    private async void ImportBundle_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "DllSidecar bundle or markdown|*.dsa;*.zip;*.md|DllSidecar bundle (*.dsa;*.zip)|*.dsa;*.zip|Markdown (*.md)|*.md|All files|*.*",
            Title = "Import advisory — .dsa bundle or .md file",
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            var ext = Path.GetExtension(dlg.FileName).ToLowerInvariant();
            if (ext == ".md")
            {
                var md = File.ReadAllText(dlg.FileName);
                var ctx = MarkdownAdvisoryImporter.Parse(md);
                var created = await _repo.CreateFromContextAsync(ctx, md);
                SetStatus($"Imported .md as Draft (id: {created.Id}) — title: {created.Title}", StatusKind.Ok);
                _main.Log($"Markdown imported: {dlg.FileName} → advisory {created.Id}");
            }
            else // .dsa or .zip — could be a single-advisory bundle OR a vendor-wrapper ZIP.
            {
                var svc = new AdvisoryBundleService(_repo);
                var imported = await ImportBundleOrWrapperAsync(svc, dlg.FileName);
                if (imported.Count == 1)
                    SetStatus($"Bundle imported (id: {imported[0]}) from {Path.GetFileName(dlg.FileName)}.", StatusKind.Ok);
                else
                    SetStatus($"Vendor wrapper imported — {imported.Count} advisory·ies added.", StatusKind.Ok);
                _main.Log($"Import '{dlg.FileName}' → {imported.Count} advisory·ies: {string.Join(", ", imported)}");
            }
            await RefreshAsync();
        }
        catch (Exception ex) { SetStatus($"Import failed: {ex.Message}", StatusKind.Err); }
    }

    /// <summary>
    /// Import a file that's either a single-advisory <c>.dsa</c> bundle OR a vendor-wrapper
    /// ZIP produced by <see cref="ExportVendorBundle_Click"/>. Wrapper detection: if the ZIP
    /// has no <c>manifest.json</c> at the root, we look for any <c>.dsa</c>/<c>.zip</c>
    /// entries inside and import each recursively.
    /// </summary>
    private static async Task<List<string>> ImportBundleOrWrapperAsync(AdvisoryBundleService svc, string zipPath)
    {
        using var zip = System.IO.Compression.ZipFile.OpenRead(zipPath);
        var isWrapper = zip.GetEntry("manifest.json") == null
                     && zip.Entries.Any(e => e.Name.EndsWith(".dsa", StringComparison.OrdinalIgnoreCase));
        if (!isWrapper)
        {
            var id = await svc.ImportAsync(zipPath);
            return new List<string> { id };
        }

        // Wrapper — extract inner .dsa files to temp and import each.
        var tempDir = Path.Combine(Path.GetTempPath(), $"dllsidecar-import-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var imported = new List<string>();
        try
        {
            var tempDirPrefix = Path.GetFullPath(tempDir) + Path.DirectorySeparatorChar;
            foreach (var entry in zip.Entries.Where(e => e.Name.EndsWith(".dsa", StringComparison.OrdinalIgnoreCase)))
            {
                // Zip Slip defense (SCS0018): strip any directory components and verify
                // the resolved path stays under tempDir. A crafted bundle entry like
                // "../../foo.dsa" would otherwise let the extractor escape tempDir.
                var safeName = Path.GetFileName(entry.Name);
                if (string.IsNullOrEmpty(safeName)) continue;
                var inner = Path.GetFullPath(Path.Combine(tempDir, safeName));
                if (!inner.StartsWith(tempDirPrefix, StringComparison.OrdinalIgnoreCase)) continue;

                entry.ExtractToFile(inner, overwrite: true);
                try { imported.Add(await svc.ImportAsync(inner)); }
                catch { /* keep going — partial imports beat aborting on one bad entry */ }
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
        return imported;
    }

    private static string SanitizeFilename(string raw)
    {
        var bad = Path.GetInvalidFileNameChars();
        var sb = new System.Text.StringBuilder(raw.Length);
        foreach (var c in raw) sb.Append(bad.Contains(c) ? '_' : c);
        return sb.ToString().Trim();
    }

    // ---- Drag and drop --------------------------------------------------
    //
    // Moves an Advisory to another Vendor (UPDATE vendor), to Trash (soft-delete), a
    // whole Vendor folder to another (merge = rename all), or a Vendor to Trash
    // (bulk soft-delete). Vendors in edit mode (double-click rename active) are
    // locked — can't drag a row you're actively renaming.
    //
    // Drop targets: VendorNode (accept Advisory or Vendor or FileLeaf-as-advisory), TrashNode
    // (accept Advisory or Vendor). Drop rejected: same node on itself, AdvisoryNode-as-target.

    private const string DragDataFormat = "DllSidecar.TreeNode";
    private System.Windows.Point? _dragStart;
    private object? _dragCandidate;

    private void Tree_PreviewMouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        // Skip drag tracking when the click originated on the expand chevron — the
        // TreeViewItem's internal ToggleButton handles expand/collapse, and recording
        // _dragStart here would let a tiny mouse jitter steal the click for drag.
        if (IsOverExpandToggle(e.OriginalSource as DependencyObject))
        {
            _dragStart = null;
            _dragCandidate = null;
            return;
        }
        _dragStart = e.GetPosition(null);
        _dragCandidate = ResolveDataContext(e.OriginalSource as DependencyObject);
    }

    private static bool IsOverExpandToggle(DependencyObject? source)
    {
        while (source != null)
        {
            if (source is System.Windows.Controls.Primitives.ToggleButton) return true;
            if (source is TreeViewItem) return false; // stop walk at the item boundary
            source = System.Windows.Media.VisualTreeHelper.GetParent(source);
        }
        return false;
    }

    private void Tree_PreviewMouseMove(object sender, System.Windows.Input.MouseEventArgs e)
    {
        if (_dragStart == null || e.LeftButton != System.Windows.Input.MouseButtonState.Pressed) return;
        var delta = e.GetPosition(null) - _dragStart.Value;

        // Use a conservative threshold (~4x the system default) so normal clicks on the
        // chevron ▸ or on a row aren't stolen by drag initiation. Touchpads fire tiny
        // move events during a click; default 4-pixel WPF threshold is too trigger-happy.
        const double DragThreshold = 16.0;
        if (Math.Abs(delta.X) < DragThreshold && Math.Abs(delta.Y) < DragThreshold) return;

        // Draggable: advisories (Trash), vendors (not in rename mode), AND file leaves
        // that know their owning advisory (main tree). FileLeaf drag has always had a
        // CanDrop case + a Tree_Drop handler that moves the whole owning advisory, but
        // the move-initiation check above was missing the case — so a file row stayed
        // un-grabbable in practice. Fixed here so "drag a file to a vendor folder"
        // matches the behaviour the comment block above promises.
        bool draggable = _dragCandidate switch
        {
            AdvisoryNode => true,
            VendorNode v => !v.IsEditing,
            FileLeafNode leaf => leaf.Owner != null,
            _ => false,
        };
        if (draggable)
        {
            _dragStart = null;
            var data = new System.Windows.DataObject(DragDataFormat, _dragCandidate);
            try { DragDrop.DoDragDrop(RecordsTree, data, System.Windows.DragDropEffects.Move); }
            catch { /* DoDragDrop can throw if the shell is busy — ignore, user can retry */ }
        }
    }

    private void Tree_DragOver(object sender, System.Windows.DragEventArgs e)
    {
        var source = e.Data.GetData(DragDataFormat);
        var target = ResolveDataContext(e.OriginalSource as DependencyObject);
        e.Effects = CanDrop(source, target) ? System.Windows.DragDropEffects.Move : System.Windows.DragDropEffects.None;
        e.Handled = true;
    }

    private async void Tree_Drop(object sender, System.Windows.DragEventArgs e)
    {
        var source = e.Data.GetData(DragDataFormat);
        var target = ResolveDataContext(e.OriginalSource as DependencyObject);
        if (!CanDrop(source, target)) return;

        try
        {
            switch (source, target)
            {
                case (AdvisoryNode adv, VendorNode dst):
                    await _repo.MoveAdvisoryToVendorAsync(adv.Item.Id, dst.Name);
                    SetStatus($"Moved '{adv.Item.Title}' → {dst.Name}.", StatusKind.Ok);
                    break;

                case (AdvisoryNode adv, TrashNode):
                    await _repo.SoftDeleteAsync(adv.Item.Id);
                    SetStatus($"Moved '{adv.Item.Title}' to Trash.", StatusKind.Ok);
                    break;

                case (VendorNode srcV, VendorNode dstV):
                    var oldName = srcV.Name == "(no vendor)" ? "" : srcV.Name;
                    var moved = await _repo.RenameVendorAsync(oldName, dstV.Name);
                    SetStatus($"Merged '{srcV.Name}' into '{dstV.Name}' — {moved} record(s).", StatusKind.Ok);
                    break;

                case (VendorNode srcV2, TrashNode):
                    foreach (var rec in srcV2.Advisories.ToList())
                        await _repo.SoftDeleteAsync(rec.Id);
                    SetStatus($"Moved {srcV2.Count} advisory·ies from '{srcV2.Name}' to Trash.", StatusKind.Ok);
                    break;

                case (FileLeafNode leaf, VendorNode dst) when leaf.Owner != null:
                    // Dragging a file moves the WHOLE advisory it belongs to (re-allocates seq
                    // and moves all its files under the destination vendor folder). The user
                    // is most likely thinking "I want this advisory under that vendor", so we
                    // act on the parent record rather than only the single rendered file.
                    await _repo.MoveAdvisoryToVendorAsync(leaf.Owner.Id, dst.Name);
                    SetStatus($"Moved '{leaf.Owner.Title}' → {dst.Name}.", StatusKind.Ok);
                    break;
            }
            await RefreshAsync();
        }
        catch (Exception ex) { SetStatus($"Drop failed: {ex.Message}", StatusKind.Err); }
    }

    private static bool CanDrop(object? source, object? target)
    {
        if (source == null || target == null || ReferenceEquals(source, target)) return false;
        // A vendor can't be dropped on itself (including same reference after refresh).
        if (source is VendorNode sv && target is VendorNode tv
            && string.Equals(sv.Name, tv.Name, StringComparison.OrdinalIgnoreCase)) return false;

        return (source, target) switch
        {
            (AdvisoryNode, VendorNode) => true,
            (AdvisoryNode, TrashNode) => true,
            (VendorNode, VendorNode) => true,
            (VendorNode, TrashNode) => true,
            (FileLeafNode l, VendorNode v) => l.Owner != null
                && !string.Equals(l.Owner.Vendor ?? "(no vendor)", v.Name, StringComparison.OrdinalIgnoreCase),
            _ => false,
        };
    }

    /// <summary>Walk up the visual tree from a hit source to find the nearest TreeViewItem's DataContext.</summary>
    private static object? ResolveDataContext(DependencyObject? source)
    {
        while (source != null)
        {
            if (source is TreeViewItem tvi) return tvi.DataContext;
            if (source is FrameworkElement fe && fe.DataContext is (VendorNode or AdvisoryNode or TrashNode or FileLeafNode))
                return fe.DataContext;
            source = System.Windows.Media.VisualTreeHelper.GetParent(source);
        }
        return null;
    }

    /// <summary>Compact view-model used for vendor/trash summary lists.</summary>
    public sealed class VendorSummaryRow
    {
        public AdvisoryRecordListItem Item { get; }
        public VendorSummaryRow(AdvisoryRecordListItem it) { Item = it; }
        public string Title => Item.Title;
        public string Status => Item.Status.ToString();
        public string Product => string.IsNullOrWhiteSpace(Item.Product) ? "—" : Item.Product!;
        public string Updated => Item.UpdatedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
    }

    private void RenderFilePreview(FileLeafNode leaf)
    {
        FilePreviewTitle.Text = leaf.Filename;
        FilePreviewPath.Text = leaf.FullPath;
        try
        {
            FilePreviewBox.Text = File.Exists(leaf.FullPath)
                ? File.ReadAllText(leaf.FullPath)
                : "(file missing on disk)";
        }
        catch (Exception ex)
        {
            FilePreviewBox.Text = $"(could not read file: {ex.Message})";
        }
    }

    private void OpenFile_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedLeaf == null) return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = _selectedLeaf.FullPath,
                UseShellExecute = true,
            });
        }
        catch (Exception ex) { SetStatus($"Open failed: {ex.Message}", StatusKind.Err); }
    }

    private void CopyFilePath_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedLeaf == null) return;
        try
        {
            System.Windows.Clipboard.SetText(_selectedLeaf.FullPath);
            SetStatus("Path copied to clipboard.", StatusKind.Ok);
        }
        catch (Exception ex) { SetStatus($"Copy failed: {ex.Message}", StatusKind.Err); }
    }

    private async void DeleteFile_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedLeaf == null) return;
        var r = MessageBox.Show($"Delete rendered file '{_selectedLeaf.Filename}'?\n\n{_selectedLeaf.FullPath}",
            "Delete artifact", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (r != MessageBoxResult.Yes) return;
        try
        {
            await _repo.DeleteArtifactAsync(_selectedLeaf.Artifact.Id);
            _main.Log($"Artifact {_selectedLeaf.Artifact.Id} deleted");
            _selectedLeaf = null;
            ShowPane(Pane.Empty);
            await RefreshAsync();
        }
        catch (Exception ex) { SetStatus($"Delete failed: {ex.Message}", StatusKind.Err); }
    }

    /// <summary>
    /// Render a loaded advisory into the details panel. Called from the grid's
    /// selection handler AND directly by actions (ChangeStatus, AddNote) after
    /// they mutate the record, so we don't have to re-trigger the selection event.
    /// </summary>
    private void RenderDetails(AdvisoryRecord r)
    {
        DetailEmpty.Visibility = Visibility.Collapsed;
        DetailContent.Visibility = Visibility.Visible;
        ActionIconsBar.Visibility = Visibility.Visible;

        DetailTitle.Text = r.Title;
        DetailSubtitle.Text = $"id: {r.Id}" +
            (string.IsNullOrEmpty(r.PeFilename) ? "" : $"  ·  {r.PeFilename}") +
            (string.IsNullOrEmpty(r.Architecture) ? "" : $"  ·  {r.Architecture}");

        DetailStatusText.Text = r.Status.ToString().ToUpperInvariant();
        var (sBg, sFg) = StatusColors(r.Status);
        DetailStatusBadge.Background = new SolidColorBrush(sBg);
        DetailStatusText.Foreground = new SolidColorBrush(sFg);

        if (r.CvssScore.HasValue)
        {
            DetailCvssBadge.Visibility = Visibility.Visible;
            DetailCvssText.Text = $"CVSS {r.CvssScore.Value:0.0} {r.CvssSeverity ?? ""}".Trim();
        }
        else DetailCvssBadge.Visibility = Visibility.Collapsed;

        var cveId = r.Links?.FirstOrDefault(l => l.LinkKind == AdvisoryLinkKind.Cve)?.Value;
        if (!string.IsNullOrEmpty(cveId))
        {
            DetailCveBadge.Visibility = Visibility.Visible;
            DetailCveText.Text = cveId;
        }
        else DetailCveBadge.Visibility = Visibility.Collapsed;

        DetailMetaVendor.Text = $"{r.Vendor ?? "(vendor —)"}  ·  {r.Product ?? "(product —)"}" +
            (string.IsNullOrEmpty(r.ProductVersion) ? "" : $"  ·  {r.ProductVersion}");
        DetailMetaPe.Text = r.PePath ?? "(no PE path recorded)";
        DetailMetaInstall.Text = r.InstallDirectory ?? "";

        var dates = new List<string>
        {
            $"created {r.CreatedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm}",
            $"updated {r.UpdatedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm}",
        };
        if (r.DiscoveredOn.HasValue) dates.Add($"discovered {r.DiscoveredOn.Value.ToLocalTime():yyyy-MM-dd}");
        if (r.ReportedOn.HasValue)   dates.Add($"reported {r.ReportedOn.Value.ToLocalTime():yyyy-MM-dd}");
        if (r.DisclosedOn.HasValue)  dates.Add($"disclosed {r.DisclosedOn.Value.ToLocalTime():yyyy-MM-dd}");
        DetailMetaDates.Text = string.Join("  ·  ", dates);

        TimelineList.ItemsSource = (r.Timeline ?? new List<AdvisoryTimelineEvent>())
            .OrderByDescending(t => t.EventAtUtc)
            .Select(t => new TimelineRow(t))
            .ToList();
    }

    private async void OpenInAdvisory_Click(object sender, RoutedEventArgs e)
    {
        if (_loaded == null) return;
        var ctx = ProjectToContext(_loaded);
        _main.PendingAdvisoryContext = ctx;
        _main.PendingAdvisoryRecordId = _loaded.Id;

        // If the user opened from a specific file leaf, edit THAT file's template — not the
        // advisory's last_template_id, which may correspond to a different artifact and would
        // cause the editor to mis-render (e.g. opening .md but seeing INCIBE selected, then
        // Save creating a duplicate file in the wrong format folder).
        if (_selectedLeaf?.Artifact != null
            && !string.IsNullOrWhiteSpace(_selectedLeaf.Artifact.TemplateId))
        {
            _main.PendingAdvisoryTemplateId = _selectedLeaf.Artifact.TemplateId;
            // Use the file's actual on-disk content as the editor seed; otherwise we'd show
            // the body of whichever artifact the advisory record's MarkdownBody column happens
            // to mirror, which is usually the LAST saved one regardless of template.
            try { _main.PendingAdvisoryMarkdown = await System.IO.File.ReadAllTextAsync(_selectedLeaf.Artifact.Path); }
            catch { _main.PendingAdvisoryMarkdown = _loaded.MarkdownBody; }
        }
        else
        {
            _main.PendingAdvisoryTemplateId = _loaded.LastTemplateId;
            _main.PendingAdvisoryMarkdown = _loaded.MarkdownBody;
        }

        _main.NavigateTo(new AdvisoryPage(_main));
    }

    private async void ChangeStatus_Click(object sender, RoutedEventArgs e)
    {
        if (_loaded == null) return;
        var id = _loaded.Id;

        // Per-format status: if a FileLeaf is the active selection (main tree, not Trash),
        // change ONLY that artifact's status. Each format (markdown / incibe / ghsa) tracks
        // its own workflow state because submission lifecycles differ — INCIBE may already
        // be in CveAssigned while Markdown is still Draft, etc.
        if (_selectedLeaf?.Artifact != null && !_selectedIsTrashed)
        {
            var artifact = _selectedLeaf.Artifact;
            var dlg = new StatusPickerDialog(artifact.Status) { Owner = Window.GetWindow(this) };
            if (dlg.ShowDialog() != true || dlg.Selected == artifact.Status) return;
            try
            {
                await _repo.UpdateArtifactStatusAsync(artifact.Id, dlg.Selected, dlg.NoteText);
                var label = artifact.TemplateId?.ToUpperInvariant() ?? "ARTIFACT";
                _main.Log($"[{label}] artifact {artifact.Id} (advisory {id}) status → {dlg.Selected}");
                await ReloadCurrentAsync(id);
            }
            catch (Exception ex) { SetStatus($"Update failed: {ex.Message}", StatusKind.Err); }
            return;
        }

        // Fallback: AdvisoryNode (Trash) or any non-leaf selection — update the whole record.
        var dlg2 = new StatusPickerDialog(_loaded.Status) { Owner = Window.GetWindow(this) };
        if (dlg2.ShowDialog() != true || dlg2.Selected == _loaded.Status) return;
        try
        {
            await _repo.UpdateStatusAsync(id, dlg2.Selected, dlg2.NoteText);
            _main.Log($"Advisory {id} status → {dlg2.Selected}");
            await ReloadCurrentAsync(id);
        }
        catch (Exception ex) { SetStatus($"Update failed: {ex.Message}", StatusKind.Err); }
    }

    private async void AddNote_Click(object sender, RoutedEventArgs e)
    {
        if (_loaded == null) return;
        var id = _loaded.Id;
        var dlg = new NotePromptDialog { Owner = Window.GetWindow(this) };
        if (dlg.ShowDialog() != true || string.IsNullOrWhiteSpace(dlg.NoteText)) return;
        try
        {
            await _repo.AddTimelineEventAsync(id, TimelineEventKind.Note, "Note", dlg.NoteText);
            await ReloadCurrentAsync(id);
        }
        catch (Exception ex) { SetStatus($"Add note failed: {ex.Message}", StatusKind.Err); }
    }

    /// <summary>
    /// Reload the currently selected record from DB and refresh both the list and detail
    /// pane in-place. Avoids fiddling with RecordsGrid.SelectedItem, which was racing
    /// with the async SelectionChanged handler and producing a NullReferenceException.
    /// </summary>
    private async Task ReloadCurrentAsync(string id)
    {
        var fresh = await _repo.GetAsync(id);
        if (fresh == null) return;
        _loaded = fresh;
        RenderDetails(fresh);
        await RefreshAsync();  // refresh the left list (grouping, updated timestamp, etc.)
    }

    private void ExpandAdvisoryDetails_Click(object sender, RoutedEventArgs e)
    {
        var host = AdvisoryDetailsHost;
        if (host == null || host.Parent is not Border originalBorder) return;
        originalBorder.Child = null;
        ExpandAdvisoryBtn.Visibility = Visibility.Collapsed;

        var modal = new DetailModalWindow("ADVISORY DETAILS", host, Window.GetWindow(this));
        modal.Closed += (_, _) =>
        {
            var content = modal.DetachContent();
            if (content is DockPanel back && originalBorder.Child == null)
                originalBorder.Child = back;
            ExpandAdvisoryBtn.Visibility = Visibility.Visible;
        };
        modal.ShowDialog();
    }

    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (_loaded == null) return;
        var r = MessageBox.Show($"Delete advisory '{_loaded.Title}'?\nThis cascades timeline, artifacts and links.",
            "Confirm delete", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (r != MessageBoxResult.Yes) return;
        try
        {
            await _repo.DeleteAsync(_loaded.Id);
            _main.Log($"Advisory {_loaded.Id} deleted");
            _loaded = null;
            DetailEmpty.Visibility = Visibility.Visible;
            DetailContent.Visibility = Visibility.Collapsed;
            ActionIconsBar.Visibility = Visibility.Collapsed;
            await RefreshAsync();
        }
        catch (Exception ex) { SetStatus($"Delete failed: {ex.Message}", StatusKind.Err); }
    }

    private static Core.Models.Advisory.AdvisoryContext ProjectToContext(AdvisoryRecord r)
    {
        // Researcher identity falls back to AppConfig when the record's stored value is blank
        // (the four PGP / INCIBE rank fields are user-level, not finding-level — only persisted
        // per-advisory when the user explicitly overrode the default at draft time).
        var researcher = Core.Configuration.ConfigManager.Current.Researcher;

        // Map back to AdvisoryContext so AdvisoryPage can re-render or let user edit.
        var ctx = new Core.Models.Advisory.AdvisoryContext
        {
            ResearcherName = r.ResearcherName,
            ResearcherHandle = r.ResearcherHandle,
            ResearcherBlog = r.ResearcherBlog,
            ResearcherEmail = r.ResearcherEmail,
            Vendor = r.Vendor,
            Product = r.Product,
            Version = r.ProductVersion,
            Architecture = r.Architecture,
            PePath = r.PePath,
            PeFilename = r.PeFilename,
            Title = r.Title,
            Cwe = r.CweId,
            CweName = r.CweName,
            VulnType = r.VulnerabilityType,
            InstallDirectory = r.InstallDirectory,
            WritableByPrincipals = r.WritableByPrincipals,
            DirectoryLowPrivWritable = r.DirectoryLowPrivWritable,
            GeneratedDllPath = r.GeneratedDllPath,
            ImporterExe = r.ImporterExe,
            PayloadDescription = r.PayloadDescription ?? "",
            CvssScore = r.CvssScore ?? 0,
            CvssSeverity = r.CvssSeverity ?? "HIGH",
            DisclosurePolicy = r.DisclosurePolicy,
            DiscoveredOn = r.DiscoveredOn ?? DateTime.Today,
            ReportedOn = r.ReportedOn,
            DisclosedOn = r.DisclosedOn,

            // Template Fields (schema v4) — direct mirrors of the persisted columns.
            VulnerabilityTypeText = r.VulnerabilityTypeText ?? "",
            VendorUrl = r.VendorUrl,
            VendorPocName = r.VendorPocName,
            VendorPocEmail = r.VendorPocEmail,
            DeviceUrlReference = r.DeviceUrlReference,
            DeviceBriefSummary = r.DeviceBriefSummary,
            AffectedComponents = r.AffectedComponents ?? "",
            PreviousRequirements = r.PreviousRequirements ?? "",
            ProposedSolution = r.ProposedSolution ?? "",
            HasContactedVendorNote = r.HasContactedVendorNote ?? "",
            CvssV4Score = r.CvssV4Score ?? 0,
            CvssV4Severity = r.CvssV4Severity ?? "HIGH",

            // Researcher overrides — null in DB means "use config".
            ResearcherPgpFingerprint = !string.IsNullOrWhiteSpace(r.ResearcherPgpFingerprint)
                ? r.ResearcherPgpFingerprint!
                : researcher.PgpFingerprint,
            ResearcherPgpKeyId = !string.IsNullOrWhiteSpace(r.ResearcherPgpKeyId)
                ? r.ResearcherPgpKeyId!
                : researcher.PgpKeyId,
            IncibeRankingOptIn = r.IncibeRankingOptIn ?? researcher.IncibeRankingOptIn,
            IncibePublicDisplayName = !string.IsNullOrWhiteSpace(r.IncibePublicDisplayName)
                ? r.IncibePublicDisplayName!
                : researcher.IncibePublicDisplayName,
        };
        // Decode CVSS v3.1 vector if stored
        if (!string.IsNullOrWhiteSpace(r.CvssVector))
            ctx.Cvss = Core.Services.Advisory.CvssCalculator.ParseVector(r.CvssVector) ?? ctx.Cvss;
        // Decode CVSS v4.0 vector if stored
        if (!string.IsNullOrWhiteSpace(r.CvssV4Vector))
            ctx.CvssV4 = Core.Services.Advisory.CvssV4Calculator.ParseVector(r.CvssV4Vector) ?? ctx.CvssV4;
        // Parse classification enums (TEXT in DB)
        if (!string.IsNullOrWhiteSpace(r.AttackType)
            && Enum.TryParse<Core.Models.Advisory.AttackType>(r.AttackType, out var atk))
            ctx.AttackType = atk;
        if (!string.IsNullOrWhiteSpace(r.ImpactCategory)
            && Enum.TryParse<Core.Models.Advisory.ImpactCategory>(r.ImpactCategory, out var imp))
            ctx.ImpactCategory = imp;

        // Records persisted before the researcher-hydration fix stored Name/Handle/Blog/Email
        // as blank strings. Re-apply the config fallback so loading an old advisory still
        // renders with the current researcher identity.
        ctx.ApplyResearcherFromConfig();

        return ctx;
    }

    // ---- row view models ---------------------------------------------------

    /// <summary>
    /// Special top-level node that shows every soft-deleted advisory. Rendered with a distinct
    /// trash glyph and gated actions (Restore / Permanent delete) instead of the rename flow.
    /// </summary>
    public sealed class TrashNode
    {
        public string Name => "Trash";
        public ObservableCollection<AdvisoryNode> Advisories { get; } = [];
        public int Count => Advisories.Count;
    }

    /// <summary>Level 1 of the tree: a vendor name grouping its advisories. Supports inline rename.</summary>
    public sealed class VendorNode : INotifyPropertyChanged
    {
        private string _name = "";
        public string Name
        {
            get => _name;
            set { if (_name != value) { _name = value; OnChanged(nameof(Name)); } }
        }
        public string OriginalName { get; set; } = "";  // stashed before edit so we can UPDATE by old key

        private bool _isEditing;
        public bool IsEditing
        {
            get => _isEditing;
            set
            {
                if (_isEditing == value) return;
                _isEditing = value;
                OnChanged(nameof(IsEditing));
                OnChanged(nameof(ViewVisibility));
                OnChanged(nameof(EditVisibility));
            }
        }
        public Visibility ViewVisibility => _isEditing ? Visibility.Collapsed : Visibility.Visible;
        public Visibility EditVisibility => _isEditing ? Visibility.Visible : Visibility.Collapsed;

        /// <summary>
        /// Files directly under this vendor (flattened across all renderers). Sorted by
        /// filename so the advisory sequence number and extension produce the natural
        /// clustering DLL_SIDELOADING_ADVISORY_NNNN.md / .txt / .yaml. The previous
        /// Vendor → FormatFolder → File hierarchy was dropped because the intermediate
        /// folder added click cost without carrying information the filename does not.
        /// </summary>
        public ObservableCollection<FileLeafNode> Files { get; } = [];

        /// <summary>
        /// Cache of advisories under this vendor. Populated alongside Files so the right-pane
        /// vendor summary can list them without re-querying the repo.
        /// </summary>
        public List<AdvisoryRecordListItem> Advisories { get; } = [];
        public int Count => Advisories.Count;

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnChanged(string n) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
    }

    /// <summary>Level 2 of the tree (Trash group only): one soft-deleted advisory with its
    /// rendered files directly underneath. Format-folder intermediates were dropped during
    /// the flatten-tree pass — Restore acts on the whole advisory anyway, so per-file
    /// grouping per renderer added a click without changing the operation.</summary>
    public sealed class AdvisoryNode
    {
        public AdvisoryRecordListItem Item { get; }
        public ObservableCollection<FileLeafNode> Files { get; } = [];
        public AdvisoryNode(AdvisoryRecordListItem it) { Item = it; }

        public string Title => Item.Title;
        public string UpdatedText => Item.UpdatedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
        public string StatusLabel => Item.Status.ToString().ToUpperInvariant();
        public System.Windows.Media.Brush StatusBg
        {
            get { var (bg, _) = StatusColors(Item.Status); return new SolidColorBrush(bg); }
        }
        public System.Windows.Media.Brush StatusFg
        {
            get { var (_, fg) = StatusColors(Item.Status); return new SolidColorBrush(fg); }
        }
    }

    /// <summary>Leaf: a single rendered file (markdown / INCIBE / GHSA / future).</summary>
    public sealed class FileLeafNode
    {
        public AdvisoryArtifact Artifact { get; }
        /// <summary>Optional record for the advisory this file represents — used by the
        /// vendor-grouped tree so the leaf can carry title/status next to the filename
        /// and so selection can load the parent advisory's details. Null in the legacy
        /// per-advisory tree (under Trash) where status comes from the surrounding node.</summary>
        public AdvisoryRecordListItem? Owner { get; }

        public FileLeafNode(AdvisoryArtifact a, AdvisoryRecordListItem? owner = null)
        {
            Artifact = a;
            Owner = owner;
        }

        public string AdvisoryId => Artifact.AdvisoryId;
        public string Filename => System.IO.Path.GetFileName(Artifact.Path);
        public string CreatedText => Artifact.CreatedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
        public string FullPath => Artifact.Path;

        // Display: title comes from the owning advisory, but the status pill comes from the
        // ARTIFACT — each format (markdown / incibe / ghsa) tracks its own workflow state so
        // changing one leaf doesn't visually flip its siblings under the same vendor.
        public string OwnerTitle => Owner?.Title ?? "";
        public Visibility OwnerTitleVisibility => Owner == null ? Visibility.Collapsed : Visibility.Visible;
        public string StatusLabel => Artifact.Status.ToString().ToUpperInvariant();
        public System.Windows.Media.Brush StatusBg
        {
            get { var (bg, _) = StatusColors(Artifact.Status); return new SolidColorBrush(bg); }
        }
        public System.Windows.Media.Brush StatusFg
        {
            get { var (_, fg) = StatusColors(Artifact.Status); return new SolidColorBrush(fg); }
        }
        public Visibility StatusVisibility => Owner == null ? Visibility.Collapsed : Visibility.Visible;

        // Format chip — Markdown and GHSA now share the .md extension, so the filename
        // alone is ambiguous in the flat tree (one advisory can have two .md siblings).
        // The chip surfaces the renderer id so the row reads unambiguously without
        // having to open each file. INCIBE keeps its .txt extension but gets a chip
        // for visual consistency.
        public string FormatLabel
        {
            get
            {
                // Coalesce null/blank up-front so AdvisoryRenderers.ById never sees null
                // (signature is non-nullable). The artifact's TemplateId can be empty when
                // the row predates the per-template wiring; falling back to "" keeps the
                // chip blank rather than throwing.
                var id = Artifact.TemplateId ?? "";
                if (id.Length == 0) return "";
                return (DllSidecar.Core.Services.Advisory.Rendering.AdvisoryRenderers.ById(id)?.Id
                        ?? id).ToUpperInvariant();
            }
        }
    }


    /// <summary>
    /// Pre-TreeView view model kept so the status-bar summary can quote counts +
    /// latest-updated without recomputing from the tree. Populated alongside _vendors.
    /// </summary>
    public sealed class RecordRow
    {
        public AdvisoryRecordListItem Item { get; }
        public RecordRow(AdvisoryRecordListItem it) { Item = it; }
        public string UpdatedText => Item.UpdatedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
    }

    public sealed class TimelineRow
    {
        public AdvisoryTimelineEvent Event { get; }
        public TimelineRow(AdvisoryTimelineEvent e) { Event = e; }

        public string KindLabel => Event.EventKind switch
        {
            TimelineEventKind.Created => "CREATED",
            TimelineEventKind.Edited => "EDITED",
            TimelineEventKind.ExportedMarkdown => "MD",
            TimelineEventKind.ExportedPdf => "PDF",
            TimelineEventKind.VendorContacted => "VENDOR",
            TimelineEventKind.VendorAcknowledged => "ACK",
            TimelineEventKind.CveRequested => "CVE REQ",
            TimelineEventKind.CveAssigned => "CVE",
            TimelineEventKind.PublicDisclosure => "PUBLIC",
            TimelineEventKind.StatusChanged => "STATUS",
            TimelineEventKind.Imported => "IMPORT",
            TimelineEventKind.Note => "NOTE",
            _ => Event.EventKind.ToString().ToUpperInvariant(),
        };
        public System.Windows.Media.Brush KindBg => new SolidColorBrush(KindBgColor(Event.EventKind));
        public System.Windows.Media.Brush KindFg => new SolidColorBrush(KindFgColor(Event.EventKind));
        public string DateText => Event.EventAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
        public string Title => Event.Title;
        public string? Note => Event.Note;
        public Visibility NoteVisibility => string.IsNullOrWhiteSpace(Event.Note) ? Visibility.Collapsed : Visibility.Visible;
    }

    // ---- color maps --------------------------------------------------------

    private static (Color bg, Color fg) StatusColors(AdvisoryStatus s) => s switch
    {
        AdvisoryStatus.Draft           => (Color.FromArgb(0x33, 0x6C, 0x70, 0x86), Color.FromRgb(0xCD, 0xD6, 0xF4)),
        AdvisoryStatus.ReadyToReport   => (Color.FromArgb(0x33, 0x0A, 0x72, 0xEF), Color.FromRgb(0x89, 0xB4, 0xFA)),
        AdvisoryStatus.SentToVendor    => (Color.FromArgb(0x33, 0xF9, 0xE2, 0xAF), Color.FromRgb(0xF9, 0xE2, 0xAF)),
        AdvisoryStatus.Acknowledged    => (Color.FromArgb(0x33, 0xA6, 0xE3, 0xA1), Color.FromRgb(0xA6, 0xE3, 0xA1)),
        AdvisoryStatus.CveRequested    => (Color.FromArgb(0x33, 0xF9, 0xE2, 0xAF), Color.FromRgb(0xF9, 0xE2, 0xAF)),
        AdvisoryStatus.CveAssigned     => (Color.FromArgb(0x33, 0x00, 0xF0, 0xA3), Color.FromRgb(0x00, 0xF0, 0xA3)),
        AdvisoryStatus.Fixed           => (Color.FromArgb(0x33, 0xA6, 0xE3, 0xA1), Color.FromRgb(0xA6, 0xE3, 0xA1)),
        AdvisoryStatus.Public          => (Color.FromArgb(0x33, 0x00, 0xF0, 0xA3), Color.FromRgb(0x00, 0xF0, 0xA3)),
        AdvisoryStatus.Closed          => (Color.FromArgb(0x33, 0x6C, 0x70, 0x86), Color.FromRgb(0xA6, 0xAD, 0xC8)),
        AdvisoryStatus.Rejected        => (Color.FromArgb(0x33, 0xF3, 0x8B, 0xA8), Color.FromRgb(0xF3, 0x8B, 0xA8)),
        _                              => (Color.FromArgb(0x33, 0x6C, 0x70, 0x86), Color.FromRgb(0xCD, 0xD6, 0xF4)),
    };

    private static Color KindBgColor(TimelineEventKind k) => k switch
    {
        TimelineEventKind.Created or TimelineEventKind.Imported => Color.FromArgb(0x33, 0x00, 0xF0, 0xA3),
        TimelineEventKind.StatusChanged => Color.FromArgb(0x33, 0x0A, 0x72, 0xEF),
        TimelineEventKind.VendorContacted or TimelineEventKind.VendorAcknowledged => Color.FromArgb(0x33, 0xF9, 0xE2, 0xAF),
        TimelineEventKind.CveRequested or TimelineEventKind.CveAssigned or TimelineEventKind.PublicDisclosure => Color.FromArgb(0x33, 0xA6, 0xE3, 0xA1),
        TimelineEventKind.ExportedPdf or TimelineEventKind.ExportedMarkdown => Color.FromArgb(0x33, 0x89, 0xB4, 0xFA),
        _ => Color.FromArgb(0x33, 0x6C, 0x70, 0x86),
    };
    private static Color KindFgColor(TimelineEventKind k) => k switch
    {
        TimelineEventKind.Created or TimelineEventKind.Imported => Color.FromRgb(0x00, 0xF0, 0xA3),
        TimelineEventKind.StatusChanged => Color.FromRgb(0x89, 0xB4, 0xFA),
        TimelineEventKind.VendorContacted or TimelineEventKind.VendorAcknowledged => Color.FromRgb(0xF9, 0xE2, 0xAF),
        TimelineEventKind.CveRequested or TimelineEventKind.CveAssigned or TimelineEventKind.PublicDisclosure => Color.FromRgb(0xA6, 0xE3, 0xA1),
        TimelineEventKind.ExportedPdf or TimelineEventKind.ExportedMarkdown => Color.FromRgb(0x89, 0xB4, 0xFA),
        _ => Color.FromRgb(0xCD, 0xD6, 0xF4),
    };

    // ---- status footer -----------------------------------------------------

    private enum StatusKind { Info, Ok, Warn, Err }
    private void SetStatus(string text, StatusKind k)
    {
        Status.Text = text;
        Status.Foreground = new SolidColorBrush(k switch
        {
            StatusKind.Ok   => Color.FromRgb(0xA6, 0xE3, 0xA1),
            StatusKind.Warn => Color.FromRgb(0xF9, 0xE2, 0xAF),
            StatusKind.Err  => Color.FromRgb(0xF3, 0x8B, 0xA8),
            _               => Color.FromRgb(0x6C, 0x70, 0x86),
        });
    }
}
