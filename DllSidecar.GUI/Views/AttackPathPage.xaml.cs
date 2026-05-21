using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DllSidecar.Core.Models;
using DllSidecar.Core.Models.Privesc;
// UseWindowsForms=true makes several common types ambiguous — alias them up front.
using Point = System.Windows.Point;
using Size = System.Windows.Size;
using FontFamily = System.Windows.Media.FontFamily;
using ColorConverter = System.Windows.Media.ColorConverter;
using Shapes = System.Windows.Shapes;
using HAlign = System.Windows.HorizontalAlignment;

namespace DllSidecar.GUI.Views;

/// <summary>
/// Horizontal timeline visualization of the discovery → exploitability flow
/// for the candidate currently focused in MainWindow.CurrentAttackFocus.
///
/// Layout:
///   • Header strip (in XAML) — title, source badge, candidate identity, severity badge
///   • Phase row (PhaseGrid) — 5 columns: Discovery / Static / Dynamic / Privesc / Score
///       each is a small evidence card with bullet items, click → deep-link to source
///   • Attack chain (ChainCanvas) — 5 pills laid out horizontally with connector arrows:
///       WRITE → LOAD → TRIGGER → PRIV → EVIDENCE
///       chain-coloured glow, EVIDENCE pulses when DynamicEvidence is attached
///
/// Reveal animation:
///   • Phase columns slide-up + fade-in left-to-right (80ms stagger)
///   • Chain pills appear in chain order (100ms stagger, starting after phases)
///   • Connector lines fade in last
///   • Hover bumps drop-shadow opacity. Click routes to relevant deep-link.
/// </summary>
public partial class AttackPathPage : Page
{
    private readonly MainWindow _main;
    private MainWindow.AttackPathFocus? _focus;

    // Held across renders so MaybeStartEvidencePulse can re-target on each refresh.
    private FrameworkElement? _evidencePill;
    private System.Windows.Media.Effects.DropShadowEffect? _evidenceGlow;
    private bool _chainResizeWired;

    public AttackPathPage(MainWindow main)
    {
        _main = main;
        InitializeComponent();
        Loaded += (_, _) => Refresh();
    }

    public void Refresh()
    {
        _focus = _main.CurrentAttackFocus;
        if (_focus == null)
        {
            EmptyState.Visibility = Visibility.Visible;
            TimelineHost.Visibility = Visibility.Collapsed;
            FocusSummary.Visibility = Visibility.Collapsed;
            SourceBadge.Visibility = Visibility.Collapsed;
            return;
        }

        EmptyState.Visibility = Visibility.Collapsed;
        TimelineHost.Visibility = Visibility.Visible;
        FocusSummary.Visibility = Visibility.Visible;
        SourceBadge.Visibility = Visibility.Visible;

        SourceBadgeText.Text = _focus.Source switch
        {
            MainWindow.AttackFocusSource.Scan         => "FROM SCAN",
            MainWindow.AttackFocusSource.RuntimeTrace => "FROM RUNTIME TRACE",
            _                                         => "FOCUSED",
        };

        FocusDllName.Text = _focus.DllName;
        FocusDllPath.Text = _focus.DllPath ?? "";

        var score = _focus.Candidate?.Score ?? _focus.Phantom?.Score;
        if (score != null)
        {
            SeverityBadgeText.Text = $"{score.Total}/10  {score.Severity.ToUpperInvariant()}";
            var (bg, fg) = SeverityColors(score.Severity);
            SeverityBadge.Background = ParseHex(bg);
            SeverityBadgeText.Foreground = ParseHex(fg);
        }
        else
        {
            SeverityBadgeText.Text = "DEGRADED";
            SeverityBadge.Background = ParseHex("#33737373");
            SeverityBadgeText.Foreground = ParseHex("#737373");
        }

        RenderTimeline();
    }

    private void RenderTimeline()
    {
        _evidencePill = null;
        _evidenceGlow = null;

        DrawPhaseColumns();
        LayoutChainCanvas();
        if (!_chainResizeWired)
        {
            // Pills + connectors are positioned by absolute canvas coordinates so they
            // need re-layout on width changes. SizeChanged is the right trigger; first
            // pass also fires during the initial layout so the diagram appears.
            ChainCanvas.SizeChanged += (_, _) => LayoutChainCanvas();
            _chainResizeWired = true;
        }

        // Defer animations until layout settles — the columns + chain pills must be
        // measured before the opacity-from-zero animations look right.
        Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Loaded,
            new Action(() =>
            {
                AnimateReveal();
                MaybeStartEvidencePulse();
            }));
    }

    // ─────────────────── Phase columns ───────────────────

    private record Phase(string Title, string ColorHex, IEnumerable<string> Items, Action OnClick, bool IsScore = false);

    private void DrawPhaseColumns()
    {
        PhaseGrid.Children.Clear();

        var phases = new[]
        {
            new Phase("DISCOVERY", "#00F0A3", BuildDiscoveryItems(),
                () => _main.NavigateTo(new ScanPage(_main))),
            new Phase("STATIC",    "#0A72EF", BuildStaticItems(),
                OpenFocusInAnalyze),
            new Phase("DYNAMIC",   "#F9E2AF", BuildDynamicItems(),
                () => _main.NavigateTo(new RuntimeTracePage(_main))),
            new Phase("PRIVESC",   "#FF5B4F", BuildPrivescItems(),
                () => _main.NavigateTo(new PrivescPage(_main))),
            new Phase("SCORE",     "#CBA6F7", BuildScoreItems(),
                OpenFocusInAnalyze, IsScore: true),
        };

        for (int i = 0; i < phases.Length; i++)
        {
            var card = BuildPhaseCard(phases[i]);
            card.Margin = new Thickness(i == 0 ? 0 : 6, 0, i == phases.Length - 1 ? 0 : 6, 0);
            Grid.SetColumn(card, i);
            PhaseGrid.Children.Add(card);
        }
    }

    private Border BuildPhaseCard(Phase phase)
    {
        var color = ParseHex(phase.ColorHex);
        var card = new Border
        {
            CornerRadius = new CornerRadius(8),
            Background = ParseHex("#171717"),
            BorderBrush = color,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(12, 10, 12, 12),
            Cursor = System.Windows.Input.Cursors.Hand,
            ToolTip = BuildPhaseTooltip(phase.Title, phase.Items),
            Tag = "phase",  // used by AnimateReveal to identify columns
        };
        var glow = new System.Windows.Media.Effects.DropShadowEffect
        {
            Color = color.Color,
            BlurRadius = 12,
            ShadowDepth = 0,
            Opacity = 0.18,
        };
        card.Effect = glow;
        card.MouseLeftButtonUp += (_, _) => phase.OnClick();
        AttachHoverGlow(card, glow, baseline: 0.18, hoverPeak: 0.55);

        var stack = new StackPanel();
        var header = new Grid();
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var title = new TextBlock
        {
            Text = phase.Title,
            FontSize = 11,
            FontWeight = FontWeights.Bold,
            Foreground = color,
            Margin = new Thickness(0, 0, 0, 8),
        };
        Grid.SetColumn(title, 0);
        header.Children.Add(title);
        // Step number badge (1..5) for the timeline reading order.
        var stepIdx = phase.Title switch
        {
            "DISCOVERY" => "1", "STATIC" => "2", "DYNAMIC" => "3",
            "PRIVESC" => "4", "SCORE" => "5", _ => "•",
        };
        var num = new Border
        {
            CornerRadius = new CornerRadius(8),
            Background = new SolidColorBrush(color.Color) { Opacity = 0.15 },
            Padding = new Thickness(6, 0, 6, 0),
            Margin = new Thickness(0, 0, 0, 6),
            VerticalAlignment = VerticalAlignment.Top,
            Child = new TextBlock
            {
                Text = stepIdx,
                FontSize = 9,
                FontWeight = FontWeights.Bold,
                Foreground = color,
            },
        };
        Grid.SetColumn(num, 1);
        header.Children.Add(num);
        stack.Children.Add(header);

        var items = phase.Items.ToList();
        if (items.Count == 0)
        {
            stack.Children.Add(new TextBlock
            {
                Text = "(no signals)",
                FontSize = 11,
                FontStyle = FontStyles.Italic,
                Foreground = ParseHex("#737373"),
            });
        }
        else
        {
            // SCORE column gets bar visualisations alongside the text. Other phases
            // are bullet lines.
            if (phase.IsScore)
            {
                AppendScoreBars(stack);
            }
            else
            {
                foreach (var item in items)
                {
                    stack.Children.Add(new TextBlock
                    {
                        Text = "·  " + item,
                        FontSize = 11,
                        Foreground = ParseHex("#EDEDED"),
                        TextTrimming = TextTrimming.CharacterEllipsis,
                        Margin = new Thickness(0, 1, 0, 1),
                    });
                }
            }
        }

        card.Child = stack;
        return card;
    }

    private void AppendScoreBars(StackPanel stack)
    {
        var score = _focus?.Candidate?.Score ?? _focus?.Phantom?.Score;
        if (score == null)
        {
            stack.Children.Add(new TextBlock
            {
                Text = "(no scored candidate)",
                FontSize = 11,
                FontStyle = FontStyles.Italic,
                Foreground = ParseHex("#737373"),
            });
            return;
        }

        AppendScoreBar(stack, "EXPLOIT", score.Exploitability, "#00F0A3");
        AppendScoreBar(stack, "IMPACT",  score.Impact,         "#FF5B4F");
        AppendScoreBar(stack, "CONF",    score.Confidence,     "#0A72EF");

        // Total + severity, bigger and bolder so it lands as the "headline" of the column.
        var (bg, fg) = SeverityColors(score.Severity);
        var totalBox = new Border
        {
            CornerRadius = new CornerRadius(4),
            Background = ParseHex(bg),
            BorderBrush = ParseHex(fg),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(8, 4, 8, 4),
            Margin = new Thickness(0, 12, 0, 0),
            HorizontalAlignment = HAlign.Stretch,
        };
        totalBox.Child = new TextBlock
        {
            Text = $"TOTAL  {score.Total}/10  ·  {score.Severity.ToUpperInvariant()}",
            FontSize = 11,
            FontWeight = FontWeights.Bold,
            Foreground = ParseHex(fg),
            HorizontalAlignment = HAlign.Center,
        };
        stack.Children.Add(totalBox);
    }

    private void AppendScoreBar(StackPanel parent, string label, int value, string colorHex)
    {
        var color = ParseHex(colorHex);
        var row = new Grid { Margin = new Thickness(0, 2, 0, 2) };
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(48) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var lbl = new TextBlock
        {
            Text = label,
            FontSize = 9,
            FontWeight = FontWeights.Bold,
            Foreground = color,
            VerticalAlignment = VerticalAlignment.Center,
        };
        Grid.SetColumn(lbl, 0);
        row.Children.Add(lbl);

        // Bar: track + filled segment proportional to value/10
        var track = new Border
        {
            Height = 6,
            CornerRadius = new CornerRadius(3),
            Background = ParseHex("#222222"),
            VerticalAlignment = VerticalAlignment.Center,
        };
        var trackGrid = new Grid();
        trackGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(value, GridUnitType.Star) });
        trackGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(Math.Max(0, 10 - value), GridUnitType.Star) });
        var fill = new Border
        {
            Height = 6,
            CornerRadius = new CornerRadius(3),
            Background = color,
        };
        Grid.SetColumn(fill, 0);
        trackGrid.Children.Add(fill);
        track.Child = trackGrid;
        Grid.SetColumn(track, 1);
        row.Children.Add(track);

        var num = new TextBlock
        {
            Text = $" {value}/10",
            FontSize = 10,
            Foreground = ParseHex("#EDEDED"),
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(8, 0, 0, 0),
        };
        Grid.SetColumn(num, 2);
        row.Children.Add(num);

        parent.Children.Add(row);
    }

    // ─────────────────── Attack chain (canvas) ───────────────────

    private record ChainSlot(string Kind, string Color, ChainStepKind StepKind);

    private void LayoutChainCanvas()
    {
        ChainCanvas.Children.Clear();
        var width = ChainCanvas.ActualWidth;
        if (width < 100) return;  // first pass before layout

        var priv = _focus?.Candidate?.Privesc ?? _focus?.Phantom?.Privesc;
        var steps = priv?.ChainSteps;

        var slots = new[]
        {
            new ChainSlot("WRITE",    "#F9E2AF", ChainStepKind.WritePrimitive),
            new ChainSlot("LOAD",     "#0A72EF", ChainStepKind.LoadVector),
            new ChainSlot("TRIGGER",  "#CBA6F7", ChainStepKind.Trigger),
            new ChainSlot("PRIV",     "#FF5B4F", ChainStepKind.Privilege),
            new ChainSlot("EVIDENCE", "#00F0A3", ChainStepKind.RuntimeEvidence),
        };

        // 5 pill slots evenly spaced; pills sized to ~85% of slot, connectors fill the gap.
        const double yCenter = 60;
        const double pillH = 78;
        var slotW = width / slots.Length;
        var pillW = Math.Max(120, slotW * 0.85);

        // Connectors first so pills paint on top.
        for (int i = 0; i < slots.Length - 1; i++)
        {
            var x1 = (i + 0.5) * slotW + pillW / 2;
            var x2 = (i + 1.5) * slotW - pillW / 2;
            DrawChainConnector(x1, x2, yCenter, slots[i].Color, slots[i + 1].Color,
                hasFlow: steps != null && steps.Any(s => s.Kind == slots[i].StepKind)
                      && steps.Any(s => s.Kind == slots[i + 1].StepKind));
        }

        for (int i = 0; i < slots.Length; i++)
        {
            var slot = slots[i];
            var step = steps?.FirstOrDefault(s => s.Kind == slot.StepKind);
            var x = (i + 0.5) * slotW;
            DrawChainPill(slot.Kind, slot.Color, step, x, yCenter, pillW, pillH);
        }
    }

    private void DrawChainPill(string kind, string colorHex, ChainStep? step,
        double cx, double cy, double w, double h)
    {
        var color = ParseHex(colorHex);
        var hasContent = step != null;

        var pill = new Border
        {
            Width = w,
            Height = h,
            CornerRadius = new CornerRadius(10),
            Background = new SolidColorBrush(color.Color)
                { Opacity = hasContent ? 0.16 : 0.05 },
            BorderBrush = hasContent ? color : new SolidColorBrush(color.Color) { Opacity = 0.35 },
            BorderThickness = new Thickness(1.5),
            Padding = new Thickness(10, 8, 10, 8),
            Tag = kind,  // used by AnimateReveal for chain-order stagger
        };

        if (hasContent)
        {
            var glow = new System.Windows.Media.Effects.DropShadowEffect
            {
                Color = color.Color,
                BlurRadius = 14,
                ShadowDepth = 0,
                Opacity = 0.45,
            };
            pill.Effect = glow;
            pill.Cursor = System.Windows.Input.Cursors.Hand;
            pill.ToolTip = BuildChainStepTooltip(kind, step!);
            pill.MouseLeftButtonUp += (_, _) => OnChainStepClick(kind, step!);
            AttachHoverGlow(pill, glow, baseline: 0.45, hoverPeak: 1.0);

            if (kind == "EVIDENCE")
            {
                _evidencePill = pill;
                _evidenceGlow = glow;
            }
        }
        else
        {
            pill.ToolTip = $"{kind} — no chain step bound (focus has no PrivescContext or this step wasn't built).";
        }

        var stack = new StackPanel();
        stack.Children.Add(new TextBlock
        {
            Text = kind,
            FontSize = 10,
            FontWeight = FontWeights.Bold,
            Foreground = hasContent ? color : new SolidColorBrush(color.Color) { Opacity = 0.5 },
        });
        stack.Children.Add(new TextBlock
        {
            Text = step?.Label ?? "—",
            FontSize = 12,
            FontWeight = FontWeights.SemiBold,
            Foreground = ParseHex(hasContent ? "#EDEDED" : "#5A5A5A"),
            TextTrimming = TextTrimming.CharacterEllipsis,
            Margin = new Thickness(0, 4, 0, 0),
        });
        if (!string.IsNullOrEmpty(step?.Detail))
        {
            stack.Children.Add(new TextBlock
            {
                Text = step.Detail,
                FontSize = 10,
                Foreground = ParseHex("#A1A1A1"),
                TextTrimming = TextTrimming.CharacterEllipsis,
                TextWrapping = TextWrapping.NoWrap,
                Margin = new Thickness(0, 2, 0, 0),
            });
        }
        pill.Child = stack;

        Canvas.SetLeft(pill, cx - w / 2);
        Canvas.SetTop(pill, cy - h / 2);
        ChainCanvas.Children.Add(pill);
    }

    private void DrawChainConnector(double x1, double x2, double y, string fromColor, string toColor, bool hasFlow)
    {
        // Gradient line + chevron tip. When hasFlow is false we dim and dash so the
        // user sees the structure but reads it as 'no data flowing here yet'.
        var gradient = new LinearGradientBrush
        {
            StartPoint = new Point(0, 0),
            EndPoint = new Point(1, 0),
        };
        gradient.GradientStops.Add(new GradientStop((Color)ColorConverter.ConvertFromString(fromColor), 0));
        gradient.GradientStops.Add(new GradientStop((Color)ColorConverter.ConvertFromString(toColor), 1));

        var line = new Shapes.Line
        {
            X1 = x1, Y1 = y, X2 = x2 - 6, Y2 = y,
            Stroke = gradient,
            StrokeThickness = hasFlow ? 2 : 1.2,
            Opacity = hasFlow ? 0.85 : 0.25,
            StrokeDashArray = hasFlow ? null : new DoubleCollection(new[] { 4.0, 3.0 }),
            Tag = "connector",
            IsHitTestVisible = false,
        };
        ChainCanvas.Children.Add(line);

        // Arrow tip — small filled triangle pointing right into the next pill.
        var tip = new Shapes.Polygon
        {
            Points = new PointCollection
            {
                new Point(x2 - 8, y - 4),
                new Point(x2 - 8, y + 4),
                new Point(x2, y),
            },
            Fill = ParseHex(toColor),
            Opacity = hasFlow ? 0.9 : 0.3,
            Tag = "connector",
            IsHitTestVisible = false,
        };
        ChainCanvas.Children.Add(tip);
    }

    // ─────────────────── Animation ───────────────────

    /// <summary>
    /// Reveal: phase columns slide-up + fade left-to-right; chain pills appear in
    /// chain order; connectors fade in last. Cubic ease-out. Each element gets
    /// its initial Opacity to 0 (and TranslateTransform.Y to a small positive
    /// offset for columns/pills) before the storyboard fires.
    /// </summary>
    private void AnimateReveal()
    {
        // Phase columns — left-to-right stagger.
        int colIdx = 0;
        foreach (var child in PhaseGrid.Children.OfType<Border>())
        {
            AttachSlideUpFade(child, delayMs: 80 + colIdx * 80);
            colIdx++;
        }

        // Chain pills — chain order stagger, starting after phases finish (~520ms).
        var pillOrder = new Dictionary<string, int>
        {
            ["WRITE"] = 0, ["LOAD"] = 1, ["TRIGGER"] = 2, ["PRIV"] = 3, ["EVIDENCE"] = 4,
        };
        foreach (var pill in ChainCanvas.Children.OfType<Border>())
        {
            if (pill.Tag is string kind && pillOrder.TryGetValue(kind, out var idx))
                AttachSlideUpFade(pill, delayMs: 540 + idx * 100);
        }

        // Connectors fade in last.
        foreach (var conn in ChainCanvas.Children.OfType<UIElement>())
        {
            if (conn is Shapes.Line || conn is Shapes.Polygon)
                AttachOpacityFade(conn, delayMs: 1100);
        }
    }

    private static void AttachSlideUpFade(FrameworkElement el, int delayMs)
    {
        var transform = new TranslateTransform(0, 14);
        el.RenderTransform = transform;
        el.Opacity = 0;

        var ease = new System.Windows.Media.Animation.CubicEase
            { EasingMode = System.Windows.Media.Animation.EasingMode.EaseOut };
        var begin = TimeSpan.FromMilliseconds(delayMs);

        el.BeginAnimation(UIElement.OpacityProperty,
            new System.Windows.Media.Animation.DoubleAnimation
            {
                From = 0, To = 1,
                Duration = TimeSpan.FromMilliseconds(380),
                BeginTime = begin,
                EasingFunction = ease,
            });
        transform.BeginAnimation(TranslateTransform.YProperty,
            new System.Windows.Media.Animation.DoubleAnimation
            {
                From = 14, To = 0,
                Duration = TimeSpan.FromMilliseconds(380),
                BeginTime = begin,
                EasingFunction = ease,
            });
    }

    private static void AttachOpacityFade(UIElement el, int delayMs)
    {
        var oldOpacity = el.Opacity;
        el.Opacity = 0;
        el.BeginAnimation(UIElement.OpacityProperty,
            new System.Windows.Media.Animation.DoubleAnimation
            {
                From = 0, To = oldOpacity == 0 ? 1 : oldOpacity,
                Duration = TimeSpan.FromMilliseconds(420),
                BeginTime = TimeSpan.FromMilliseconds(delayMs),
                EasingFunction = new System.Windows.Media.Animation.CubicEase
                    { EasingMode = System.Windows.Media.Animation.EasingMode.EaseOut },
            });
    }

    private void MaybeStartEvidencePulse()
    {
        if (_evidenceGlow == null) return;
        var ev = _focus?.Candidate?.Evidence ?? _focus?.Phantom?.Evidence;
        if (ev == null && _focus?.Source != MainWindow.AttackFocusSource.RuntimeTrace) return;

        var anim = new System.Windows.Media.Animation.DoubleAnimation
        {
            From = 0.45,
            To = 1.0,
            Duration = TimeSpan.FromSeconds(1.1),
            BeginTime = TimeSpan.FromMilliseconds(1400),
            AutoReverse = true,
            RepeatBehavior = System.Windows.Media.Animation.RepeatBehavior.Forever,
            EasingFunction = new System.Windows.Media.Animation.SineEase
                { EasingMode = System.Windows.Media.Animation.EasingMode.EaseInOut },
        };
        _evidenceGlow.BeginAnimation(
            System.Windows.Media.Effects.DropShadowEffect.OpacityProperty, anim);
    }

    // ─────────────────── Build*Items helpers ───────────────────

    private IEnumerable<string> BuildDiscoveryItems()
    {
        if (_focus == null) yield break;
        if (_focus.Candidate != null) yield return $"Sideload scanner — {_focus.Candidate.Discovery}";
        if (_focus.Phantom != null) yield return "Phantom detector (IAT slot)";
        if (_focus.Source == MainWindow.AttackFocusSource.RuntimeTrace ||
            (_focus.Candidate?.Evidence?.Source == EvidenceSource.RuntimeTrace) ||
            (_focus.Phantom?.Evidence?.Source == EvidenceSource.RuntimeTrace))
            yield return $"Runtime ETW{(_focus.RuntimeProcess != null ? $" — {_focus.RuntimeProcess}" : "")}";
        var ev = _focus.Candidate?.Evidence ?? _focus.Phantom?.Evidence;
        if (ev?.Source == EvidenceSource.ProcmonCsv) yield return "ProcMon CSV correlation";
    }

    private IEnumerable<string> BuildStaticItems()
    {
        if (_focus == null) yield break;
        var dir = _focus.Candidate?.Dir ?? _focus.Phantom?.Dir;
        if (dir != null)
        {
            var label = dir.IsLowPrivWritable ? "Dir: LOW-PRIV writable"
                      : dir.CurrentUserWrite  ? "Dir: user-writable"
                      : "Dir: admin-only";
            yield return label;
        }
        if (_focus.Candidate != null)
        {
            yield return $"DLL signing: {_focus.Candidate.DllSigning.Status}";
            var imps = _focus.Candidate.Importers;
            var signed = imps.Count(i => i.Signing.IsTrusted);
            yield return $"Importers: {imps.Count}{(signed > 0 ? $" ({signed} signed)" : "")}";
            if (imps.All(i => i.ForcesSystem32Only) && imps.Count > 0)
                yield return "All forced SYSTEM32 (penalty)";
        }
        else if (_focus.Phantom != null)
        {
            yield return "DLL: phantom slot (no file)";
            var imps = _focus.Phantom.Importers;
            yield return $"Importers: {imps.Count}";
        }
    }

    private IEnumerable<string> BuildDynamicItems()
    {
        if (_focus == null) yield break;
        var ev = _focus.Candidate?.Evidence ?? _focus.Phantom?.Evidence;
        if (ev == null && _focus.Source == MainWindow.AttackFocusSource.RuntimeTrace)
        {
            yield return $"Runtime: {_focus.RuntimeEventCount} event(s)";
            if (!string.IsNullOrEmpty(_focus.RuntimeProcess)) yield return $"Process: {_focus.RuntimeProcess}";
            yield break;
        }
        if (ev == null) yield break;
        yield return $"{(ev.Source == EvidenceSource.RuntimeTrace ? "Runtime trace" : "ProcMon")}: {ev.EventCount} events";
        yield return ev.MatchedByDirectory ? "Match: NAME+DIR (ground truth)" : "Match: name only";
        if (ev.Processes.Count > 0)
            yield return $"Processes: {string.Join(", ", ev.Processes.Take(2))}";
    }

    private IEnumerable<string> BuildPrivescItems()
    {
        if (_focus == null) yield break;
        var priv = _focus.Candidate?.Privesc ?? _focus.Phantom?.Privesc;
        if (priv == null || priv.Findings.Count == 0)
        {
            yield return "(no privesc path detected)";
            yield break;
        }
        foreach (var f in priv.Findings.OrderByDescending(f => f.Severity).Take(4))
        {
            var label = f.Vector switch
            {
                PrivescVector.ScheduledTask  => "Task: ",
                PrivescVector.ServiceSystem  => "Service: ",
                PrivescVector.AutoElevate    => "autoElevate: ",
                PrivescVector.UpdaterHeuristic => "Updater: ",
                _ => $"{f.Vector}: ",
            };
            yield return label + (f.Title ?? "");
        }
    }

    private IEnumerable<string> BuildScoreItems()
    {
        // Bullet variant (used in tooltip). The visible card uses bars instead.
        var s = _focus?.Candidate?.Score ?? _focus?.Phantom?.Score;
        if (s == null) yield break;
        yield return $"Exploit: {s.Exploitability}/10";
        yield return $"Impact:  {s.Impact}/10";
        yield return $"Conf:    {s.Confidence}/10  ({s.ConfidenceLevel})";
        yield return $"Total:   {s.Total}/10  [{s.Severity}]";
    }

    // ─────────────────── Tooltips / hover / clicks ───────────────────

    private static string BuildPhaseTooltip(string title, IEnumerable<string> items)
    {
        var lines = new List<string> { title };
        var list = items.ToList();
        if (list.Count == 0) lines.Add("(no signals)");
        else lines.AddRange(list.Select(it => "  · " + it));
        lines.Add("");
        lines.Add(title switch
        {
            "DISCOVERY" => "Click → Scan page",
            "STATIC"    => "Click → Scan DLL / Binary",
            "DYNAMIC"   => "Click → Runtime Trace",
            "PRIVESC"   => "Click → Privesc Surface",
            "SCORE"     => "Click → Scan DLL / Binary",
            _ => "",
        });
        return string.Join("\n", lines);
    }

    private static string BuildChainStepTooltip(string kindLabel, ChainStep step)
    {
        var lines = new List<string>
        {
            $"{kindLabel} — {step.Label}",
        };
        if (!string.IsNullOrEmpty(step.Detail)) lines.Add(step.Detail);
        lines.Add("");
        lines.Add(kindLabel switch
        {
            "WRITE"    => "Write primitive — directory ACL drives this step.",
            "LOAD"     => "Click → Scan DLL / Binary",
            "TRIGGER"  => "Click → open the privesc finding source.",
            "PRIV"     => "Privilege gained when the chain fires.",
            "EVIDENCE" => "Click → open Runtime Trace.",
            _ => "",
        });
        return string.Join("\n", lines);
    }

    /// <summary>Bumps drop-shadow opacity on hover, reverts on leave.</summary>
    private static void AttachHoverGlow(
        FrameworkElement el,
        System.Windows.Media.Effects.DropShadowEffect glow,
        double baseline,
        double hoverPeak)
    {
        el.MouseEnter += (_, _) =>
        {
            glow.BeginAnimation(System.Windows.Media.Effects.DropShadowEffect.OpacityProperty,
                new System.Windows.Media.Animation.DoubleAnimation
                    { To = hoverPeak, Duration = TimeSpan.FromMilliseconds(180) });
        };
        el.MouseLeave += (_, _) =>
        {
            glow.BeginAnimation(System.Windows.Media.Effects.DropShadowEffect.OpacityProperty,
                new System.Windows.Media.Animation.DoubleAnimation
                    { To = baseline, Duration = TimeSpan.FromMilliseconds(220) });
        };
    }

    private void OpenFocusInAnalyze()
    {
        if (_focus == null) return;
        if (_focus.Candidate != null)
        {
            _main.CurrentAnalysis = _focus.Candidate.Dll;
            _main.CurrentDllPath = _focus.Candidate.Dll.Path;
            _main.NavigateTo(new AnalyzePage(_main));
            return;
        }
        if (_focus.Phantom != null)
        {
            // Importer EXE path is the first preference (analyzing the binary
            // that imports the phantom is the actionable next step). But ETW
            // process events frequently expose only ProcessName as ProcessImagePath,
            // so ImporterRef.ExePath can be a bare filename like "Battle.net.exe".
            // When that's the case fall back to the phantom's synthesized path
            // (DirectoryPath + DllName) so AnalyzePage's FilePathBox shows a
            // full path the user can act on, not a stranded filename.
            string? target = null;
            var imp = _focus.Phantom.Importers.FirstOrDefault();
            if (imp != null && !string.IsNullOrEmpty(imp.ExePath)
                && Path.IsPathRooted(imp.ExePath) && File.Exists(imp.ExePath))
            {
                target = imp.ExePath;
            }
            else if (!string.IsNullOrEmpty(_focus.DllPath))
            {
                target = _focus.DllPath;
            }
            else if (!string.IsNullOrEmpty(_focus.Phantom.DirectoryPath)
                  && !string.IsNullOrEmpty(_focus.Phantom.DllName))
            {
                target = Path.Combine(_focus.Phantom.DirectoryPath, _focus.Phantom.DllName);
            }
            if (target == null) return;
            _main.CurrentAnalysis = null;
            _main.CurrentDllPath = target;
            _main.NavigateTo(new AnalyzePage(_main));
            return;
        }
        if (!string.IsNullOrEmpty(_focus.DllPath))
        {
            _main.CurrentAnalysis = null;
            _main.CurrentDllPath = _focus.DllPath;
            _main.NavigateTo(new AnalyzePage(_main));
        }
    }

    private void OnChainStepClick(string kindLabel, ChainStep step)
    {
        switch (kindLabel)
        {
            case "LOAD":
                OpenFocusInAnalyze();
                return;
            case "EVIDENCE":
                _main.NavigateTo(new RuntimeTracePage(_main));
                return;
            case "TRIGGER":
            case "PRIV":
                _main.NavigateTo(new PrivescPage(_main));
                return;
            default:
                _main.Log($"[AttackPath] {kindLabel}: {step.Label} — {step.Detail}");
                return;
        }
    }

    private void SeverityBadge_Click(object sender, RoutedEventArgs e) => OpenFocusInAnalyze();

    // ─────────────────── Helpers ───────────────────

    private static SolidColorBrush ParseHex(string hex)
    {
        var b = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
        b.Freeze();
        return b;
    }

    private static (string Bg, string Fg) SeverityColors(string severity) => severity switch
    {
        "Critical" => ("#33FF5B4F", "#FF5B4F"),
        "High"     => ("#33F5A524", "#F5A524"),
        "Medium"   => ("#330A72EF", "#0A72EF"),
        "Low"      => ("#3300CA4E", "#00CA4E"),
        _          => ("#33737373", "#737373"),
    };

    // ─────────────────── Empty-state nav ───────────────────

    private void GoScan_Click(object sender, RoutedEventArgs e) =>
        _main.NavigateTo(new ScanPage(_main));

    private void GoRuntime_Click(object sender, RoutedEventArgs e) =>
        _main.NavigateTo(new RuntimeTracePage(_main));
}
