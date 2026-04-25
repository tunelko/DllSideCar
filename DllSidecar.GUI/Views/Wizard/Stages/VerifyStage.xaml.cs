using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models.Wizard;
using DllSidecar.Core.Services;

namespace DllSidecar.GUI.Views.Wizard.Stages;

public partial class VerifyStage : System.Windows.Controls.UserControl, IWizardStage
{
    private readonly WizardSession _session;
    private readonly WizardPage _shell;

    public VerifyStage(WizardSession session, WizardPage shell)
    {
        _session = session;
        _shell = shell;
        InitializeComponent();

        if (!string.IsNullOrEmpty(_session.ProcmonCsvPath))
            ProcmonLine.Text = $"Loaded: {System.IO.Path.GetFileName(_session.ProcmonCsvPath)}";
    }

    public bool CanSkip => true;

    public Task<bool> ValidateAndCommit() => Task.FromResult(true);
    public Task OnSkip() => Task.CompletedTask;

    private async void LoadProcmon_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Filter = "ProcMon CSV|*.csv|All files|*.*" };
        if (dlg.ShowDialog() != true) return;

        _shell.ShowOverlay("Parsing ProcMon CSV", System.IO.Path.GetFileName(dlg.FileName));
        try
        {
            var parsed = await Task.Run(() => ProcmonParser.Parse(dlg.FileName));
            if (!string.IsNullOrEmpty(parsed.Error))
            {
                ProcmonLine.Text = $"Error: {parsed.Error}";
                return;
            }
            _session.ProcmonCsvPath = dlg.FileName;
            if (_session.ScanResults != null)
            {
                var report = ProcmonCorrelator.Correlate(_session.ScanResults, parsed);
                ProcmonLine.Text = $"{parsed.FilteredRows} events · correlated: " +
                                   $"{report.ExistingMatched} existing + {report.PhantomMatched} phantom";
            }
            else
            {
                ProcmonLine.Text = $"{parsed.FilteredRows} events (scan results not available)";
            }
        }
        catch (Exception ex)
        {
            Log.Error("wizard.verify.procmon", "ProcMon parse failed", ex);
            ProcmonLine.Text = $"Error: {ex.Message}";
        }
        finally { _shell.HideOverlay(); _shell.RefreshChrome(); }
    }

}
