using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DllSidecar.Core.Logging;
using DllSidecar.Core.Models.Wizard;
using DllSidecar.Core.Services.Wizard;
using DllSidecar.GUI.Views.Wizard.Stages;

namespace DllSidecar.GUI.Views.Wizard;

/// <summary>Wizard shell: hosts the current stage UserControl, drives navigation, and renders chrome.</summary>
public partial class WizardPage : Page
{
    private readonly MainWindow _main;
    private readonly WizardSession _session;
    private IWizardStage? _activeStage;

    private static readonly (WizardStage Stage, string Name)[] StageList =
    [
        (WizardStage.Input,  "INPUT"),
        (WizardStage.Survey, "SURVEY"),
        (WizardStage.Verify, "VERIFY"),
        (WizardStage.Pick,   "PICK"),
        (WizardStage.Craft,  "CRAFT"),
        (WizardStage.Report, "REPORT"),
    ];

    public WizardPage(MainWindow main)
    {
        _main = main;
        InitializeComponent();

        // Adopt any in-flight session; new session only if none exists.
        _session = _main.CurrentWizardSession ?? new WizardSession();
        _main.CurrentWizardSession = _session;

        // Resume stage priority: RuntimeTrace promote → ScanResults → persisted stage → Input.
        WizardStage resumeStage;
        if (_session.EntryPoint == WizardEntryPoint.RuntimeTrace
            && _main.LastScanResults != null
            && _session.ScanResults == null)
        {
            _session.ScanResults = _main.LastScanResults;
            _session.SurveyRootDir = _main.LastScanDir;
            resumeStage = WizardStage.Survey;
        }
        else if (_session.ScanResults != null)
        {
            resumeStage = WizardStage.Survey;
        }
        else if (_session.CurrentStage > WizardStage.Input)
        {
            resumeStage = _session.CurrentStage;
        }
        else
        {
            resumeStage = WizardStage.Input;
        }

        // Seed HUNTING FOR radios from session; handlers write back to _session.HuntingGoal.
        switch (_session.HuntingGoal)
        {
            case WizardHuntingGoal.LocalPrivesc: GoalPrivesc.IsChecked = true; break;
            case WizardHuntingGoal.Persistence:  GoalPersist.IsChecked = true; break;
            default:                             GoalCode.IsChecked = true; break;
        }
        UpdateGoalHint();

        ShowStage(resumeStage);
    }

    private void Goal_Changed(object sender, RoutedEventArgs e)
    {
        if (GoalHint == null) return; // fires during InitializeComponent
        _session.HuntingGoal = GoalPrivesc.IsChecked == true ? WizardHuntingGoal.LocalPrivesc
                             : GoalPersist.IsChecked == true ? WizardHuntingGoal.Persistence
                             : WizardHuntingGoal.ArbitraryCode;
        UpdateGoalHint();
    }

    private void UpdateGoalHint()
    {
        if (GoalHint == null) return;
        GoalHint.Text = _session.HuntingGoal switch
        {
            WizardHuntingGoal.LocalPrivesc =>
                "Looking for user → SYSTEM. Survey ranks SYSTEM services, AutoElevate manifests, scheduled tasks higher.",
            WizardHuntingGoal.Persistence =>
                "Reboot-surviving vectors. Survey favours COM hijacks, writable Program Files, startup folder drops.",
            _ =>
                "Code execution in the user's context — the common case. Survey ranks by exploitability + writable ACLs.",
        };
    }

    // ---------- Stage navigation ----------

    private void ShowStage(WizardStage stage)
    {
        _session.CurrentStage = stage;
        // Checkpoint to disk on every stage transition.
        WizardSessionStore.Save(_session);
        _activeStage = stage switch
        {
            WizardStage.Input  => new InputStage(_session, this),
            WizardStage.Survey => new SurveyStage(_session, this),
            WizardStage.Verify => new VerifyStage(_session, this),
            WizardStage.Pick   => new PickStage(_session, this),
            WizardStage.Craft  => new CraftStage(_session, this),
            WizardStage.Report => new ReportStage(_session, this, _main),
            _ => null,
        };
        StageHost.Content = _activeStage as System.Windows.Controls.UserControl;
        RenderStepper();
        RenderSessionSummary();
        RenderNavButtons();
    }

    private void RenderStepper()
    {
        var current = (int)_session.CurrentStage;
        var items = new List<StepperItem>();
        for (int i = 0; i < StageList.Length; i++)
        {
            var state = i < current ? StepperState.Done :
                        i == current ? StepperState.Current :
                                       StepperState.Pending;
            items.Add(new StepperItem(
                Name: StageList[i].Name,
                Step: i + 1,
                State: state,
                IsFirst: i == 0,
                IsLast: i == StageList.Length - 1));
        }
        StepperItems.ItemsSource = items;
    }

    private void RenderSessionSummary()
    {
        var s = _session;
        var parts = new List<string>();
        if (!string.IsNullOrEmpty(s.InputPath)) parts.Add($"input: {System.IO.Path.GetFileName(s.InputPath)}");
        if (s.ScanResults != null)
            parts.Add($"scan: {s.ScanResults.ExistingCount} existing + {s.ScanResults.PhantomCount} phantoms");
        if (s.CveDedup != null)
            parts.Add($"cve: {s.CveDedup.Matches.Count} hits ({s.CveDedup.ExactCount} exact)");
        if (s.ChosenExisting != null || s.ChosenPhantom != null)
            parts.Add($"target: {s.ChosenLabel}");
        if (!string.IsNullOrEmpty(s.BuiltDllPath))
            parts.Add($"built: {System.IO.Path.GetFileName(s.BuiltDllPath)}");
        if (s.AdvisoryMarkdown != null)
            parts.Add("advisory: drafted");

        SessionSummary.Text = parts.Count == 0 ? "(empty — no input yet)" : string.Join("  ·  ", parts);
    }

    private void RenderNavButtons()
    {
        BackBtn.IsEnabled = _session.CurrentStage > WizardStage.Input;
        SkipBtn.Visibility = (_activeStage?.CanSkip == true) ? Visibility.Visible : Visibility.Collapsed;
        ContinueBtn.Content = _session.CurrentStage switch
        {
            WizardStage.Report => "Finish",
            _ => "Continue →",
        };
    }

    // ---------- Nav button handlers ----------

    private async void Continue_Click(object sender, RoutedEventArgs e)
    {
        if (_activeStage == null) return;
        try
        {
            ContinueBtn.IsEnabled = false;
            var ok = await _activeStage.ValidateAndCommit();
            if (!ok) return;

            var next = _session.CurrentStage + 1;
            if (next > WizardStage.Report)
            {
                FinishWizard();
                return;
            }
            ShowStage(next);
        }
        catch (Exception ex)
        {
            Log.Error("wizard", "Stage commit failed", ex);
            MessageBox.Show($"Stage commit failed: {ex.Message}",
                "Wizard error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            ContinueBtn.IsEnabled = true;
        }
    }

    private void Back_Click(object sender, RoutedEventArgs e)
    {
        if (_session.CurrentStage == WizardStage.Input) return;
        ShowStage(_session.CurrentStage - 1);
    }

    private async void Skip_Click(object sender, RoutedEventArgs e)
    {
        if (_activeStage?.CanSkip != true) return;
        await _activeStage.OnSkip();
        var next = _session.CurrentStage + 1;
        if (next > WizardStage.Report) FinishWizard();
        else ShowStage(next);
    }

    private void FinishWizard()
    {
        MessageBox.Show("Wizard complete.\n\nThe advisory draft is available on the Advisory page (which stays populated until you navigate away).",
            "Done", MessageBoxButton.OK, MessageBoxImage.Information);
        _main.CurrentWizardSession = null;
        WizardSessionStore.Delete();
        _main.NavigateTo(new AdvisoryPage(_main));
    }

    // ---------- Helpers for stages to drive the shell ----------

    public void RefreshChrome()
    {
        RenderSessionSummary();
        RenderNavButtons();
        // Chrome refresh is a state-change signal → checkpoint.
        WizardSessionStore.Save(_session);
    }

    public void ShowOverlay(string title, string? subtitle = null) => Overlay.Show(title, subtitle);
    public void HideOverlay() => Overlay.Hide();
    public void LogInfo(string msg) => _main.Log(msg);

    /// <summary>Called by InputStage when the user picks the Runtime trace entry point.</summary>
    public void PivotToRuntimeTrace()
    {
        _main.Log("Wizard → Runtime trace (pivot). Promote phantoms to re-enter via Scan.");
        _main.NavigateTo(new RuntimeTracePage(_main));
    }

    // ---------- Stepper view-model ----------

    public enum StepperState { Pending, Current, Done }

    public record StepperItem(string Name, int Step, StepperState State, bool IsFirst, bool IsLast)
    {
        public string StepLabel => State == StepperState.Done ? "✓" : Step.ToString();

        public System.Windows.Media.Brush CircleFill => State switch
        {
            StepperState.Done    => Freeze(new SolidColorBrush(Color.FromRgb(0x00, 0xF0, 0xA3))),  // phosphor green
            StepperState.Current => Freeze(new SolidColorBrush(Color.FromRgb(0x11, 0x11, 0x11))),  // mantle
            _                    => Freeze(new SolidColorBrush(Color.FromRgb(0x11, 0x11, 0x11))),
        };

        public System.Windows.Media.Brush CircleStroke => State switch
        {
            StepperState.Done    => Freeze(new SolidColorBrush(Color.FromRgb(0x00, 0xF0, 0xA3))),
            StepperState.Current => Freeze(new SolidColorBrush(Color.FromRgb(0x00, 0xF0, 0xA3))),
            _                    => Freeze(new SolidColorBrush(Color.FromArgb(0x3D, 0xFF, 0xFF, 0xFF))),
        };

        public System.Windows.Media.Brush NumberFg => State switch
        {
            StepperState.Done    => Freeze(new SolidColorBrush(Color.FromRgb(0x0A, 0x0A, 0x0A))),  // dark ink on green
            StepperState.Current => Freeze(new SolidColorBrush(Color.FromRgb(0x00, 0xF0, 0xA3))),
            _                    => Freeze(new SolidColorBrush(Color.FromRgb(0x73, 0x73, 0x73))),
        };

        public System.Windows.Media.Brush LabelFg => State switch
        {
            StepperState.Current => Freeze(new SolidColorBrush(Color.FromRgb(0xED, 0xED, 0xED))),
            StepperState.Done    => Freeze(new SolidColorBrush(Color.FromRgb(0x00, 0xC4, 0x87))),  // phosphor dim
            _                    => Freeze(new SolidColorBrush(Color.FromRgb(0x73, 0x73, 0x73))),
        };

        public System.Windows.Media.Brush LeftConnector => State >= StepperState.Current
            ? Freeze(new SolidColorBrush(Color.FromRgb(0x00, 0xF0, 0xA3)))
            : Freeze(new SolidColorBrush(Color.FromArgb(0x33, 0xFF, 0xFF, 0xFF)));

        public System.Windows.Media.Brush RightConnector => State == StepperState.Done
            ? Freeze(new SolidColorBrush(Color.FromRgb(0x00, 0xF0, 0xA3)))
            : Freeze(new SolidColorBrush(Color.FromArgb(0x33, 0xFF, 0xFF, 0xFF)));

        public Visibility LeftConnectorVisibility => IsFirst ? Visibility.Hidden : Visibility.Visible;
        public Visibility RightConnectorVisibility => IsLast ? Visibility.Hidden : Visibility.Visible;

        private static System.Windows.Media.Brush Freeze(SolidColorBrush b) { b.Freeze(); return b; }
    }
}

/// <summary>Contract every wizard stage implements so the shell can drive nav.</summary>
public interface IWizardStage
{
    bool CanSkip { get; }
    Task<bool> ValidateAndCommit();
    Task OnSkip();
}
