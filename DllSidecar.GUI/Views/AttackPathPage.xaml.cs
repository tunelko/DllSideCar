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
/// Radial visualization of the full discovery → exploitability flow for the
/// candidate currently focused in MainWindow.CurrentAttackFocus.
///
/// Layout (Canvas 900×700, centred at 450,350):
///   • Outer cards at compass positions (N=Discovery, E=Static, S=Dynamic, W=Privesc)
///   • Middle ring (r=200): 5 chain step nodes at angles 0°/72°/144°/216°/288°
///       — convention: 0° = 12 o'clock, increasing clockwise.
///   • Inner ring (r≈90..130): annular sectors per scoring axis (Exploit 50%,
///       Impact 30%, Confidence 20%), starting at 0° going clockwise.
///   • Center badge (r=60): Total / Severity / DLL name.
///
/// Connectors, hover/click, and animation land in subsequent steps.
/// </summary>
public partial class AttackPathPage : Page
{
    private readonly MainWindow _main;
    private MainWindow.AttackPathFocus? _focus;

    private const double CenterX = 450;
    private const double CenterY = 350;
    private const double RingCenter = 60;
    private const double RingInnerLo = 90;
    private const double RingInnerHi = 130;
    private const double RingMiddle = 200;
    private const double RingOuterDecor = 280;

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
            DiagramHost.Visibility = Visibility.Collapsed;
            FocusSummary.Visibility = Visibility.Collapsed;
            SourceBadge.Visibility = Visibility.Collapsed;
            return;
        }

        EmptyState.Visibility = Visibility.Collapsed;
        DiagramHost.Visibility = Visibility.Visible;
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
            var (bg, fg) = score.Severity switch
            {
                "Critical" => ("#33FF5B4F", "#FF5B4F"),
                "High"     => ("#33F5A524", "#F5A524"),
                "Medium"   => ("#330A72EF", "#0A72EF"),
                "Low"      => ("#3300CA4E", "#00CA4E"),
                _          => ("#33737373", "#737373"),
            };
            SeverityBadge.Background = ParseHex(bg);
            SeverityBadgeText.Foreground = ParseHex(fg);
        }
        else
        {
            SeverityBadgeText.Text = "DEGRADED";
            SeverityBadge.Background = ParseHex("#33737373");
            SeverityBadgeText.Foreground = ParseHex("#737373");
        }

        RenderDiagram();
    }

    private void RenderDiagram()
    {
        DiagramCanvas.Children.Clear();
        if (_focus == null) return;

        DrawDecorativeRings();
        DrawScoreSectors();
        // Connectors run beneath the chain pills + centre badge so the latter
        // visually "land on top of" their incoming evidence lines.
        DrawConnectors();
        DrawCenterBadge();
        DrawChainNodes();
        DrawOuterCards();
    }

    // ─────────────────── Geometry helpers ───────────────────

    /// <summary>Polar to canvas. 0° = 12 o'clock, increasing clockwise.</summary>
    private static (double X, double Y) Polar(double cx, double cy, double r, double angleDeg)
    {
        var rad = angleDeg * Math.PI / 180.0;
        return (cx + r * Math.Sin(rad), cy - r * Math.Cos(rad));
    }

    private static SolidColorBrush ParseHex(string hex)
    {
        var b = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
        b.Freeze();
        return b;
    }

    /// <summary>
    /// Build an annular sector path figure (donut wedge) from <paramref name="angleA"/> to
    /// <paramref name="angleB"/> (CW, both in our 0°=top convention) bounded by
    /// <paramref name="rIn"/> and <paramref name="rOut"/> radii.
    /// </summary>
    private static PathFigure AnnularSector(
        double cx, double cy, double rIn, double rOut, double angleA, double angleB)
    {
        var (sxOut, syOut) = Polar(cx, cy, rOut, angleA);
        var (exOut, eyOut) = Polar(cx, cy, rOut, angleB);
        var (exIn,  eyIn)  = Polar(cx, cy, rIn,  angleB);
        var (sxIn,  syIn)  = Polar(cx, cy, rIn,  angleA);
        var isLarge = (angleB - angleA) > 180.0;

        var fig = new PathFigure { StartPoint = new Point(sxOut, syOut), IsClosed = true };
        fig.Segments.Add(new ArcSegment(new Point(exOut, eyOut), new Size(rOut, rOut), 0, isLarge, SweepDirection.Clockwise, true));
        fig.Segments.Add(new LineSegment(new Point(exIn, eyIn), true));
        fig.Segments.Add(new ArcSegment(new Point(sxIn, syIn), new Size(rIn, rIn), 0, isLarge, SweepDirection.Counterclockwise, true));
        return fig;
    }

    // ─────────────────── Draw: decorative rings ───────────────────

    private void DrawDecorativeRings()
    {
        // Three faint guide rings give the diagram visual structure. Stroke only.
        foreach (var r in new[] { RingOuterDecor, RingMiddle, RingInnerHi })
        {
            var ring = new Shapes.Ellipse
            {
                Width = r * 2,
                Height = r * 2,
                Stroke = ParseHex("#22FFFFFF"),
                StrokeThickness = 1,
                Fill = null,
                IsHitTestVisible = false,
            };
            Canvas.SetLeft(ring, CenterX - r);
            Canvas.SetTop(ring, CenterY - r);
            DiagramCanvas.Children.Add(ring);
        }
    }

    // ─────────────────── Draw: score sectors (inner ring) ───────────────────

    private void DrawScoreSectors()
    {
        var score = _focus?.Candidate?.Score ?? _focus?.Phantom?.Score;
        if (score == null)
        {
            // Degraded view — just draw a faint ring with "no score" hint.
            var ph = new TextBlock
            {
                Text = "(no scored candidate — pick one from Scan)",
                Foreground = ParseHex("#737373"),
                FontSize = 11,
                IsHitTestVisible = false,
            };
            ph.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
            Canvas.SetLeft(ph, CenterX - ph.DesiredSize.Width / 2);
            Canvas.SetTop(ph, CenterY + RingInnerHi + 4);
            DiagramCanvas.Children.Add(ph);
            return;
        }

        // Sweep allocation matches the weighted Total formula. CW from 12 o'clock.
        // Exploit dominates visually, mirroring its 50% weight.
        var segments = new[]
        {
            (Label: "EXPLOIT", Value: score.Exploitability, Sweep: 180.0, Color: "#00F0A3"),
            (Label: "IMPACT",  Value: score.Impact,         Sweep: 108.0, Color: "#FF5B4F"),
            (Label: "CONF",    Value: score.Confidence,     Sweep:  72.0, Color: "#0A72EF"),
        };

        double cursor = 0;
        foreach (var s in segments)
        {
            var endAngle = cursor + s.Sweep;
            var fig = AnnularSector(CenterX, CenterY, RingInnerLo, RingInnerHi, cursor, endAngle - 0.5);
            var geo = new PathGeometry();
            geo.Figures.Add(fig);

            var path = new Shapes.Path
            {
                Data = geo,
                Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString(s.Color)) { Opacity = 0.22 },
                Stroke = ParseHex(s.Color),
                StrokeThickness = 1.2,
            };
            DiagramCanvas.Children.Add(path);

            // Sector label: positioned slightly outside the inner ring at the centre angle.
            var midAngle = cursor + s.Sweep / 2;
            var (lx, ly) = Polar(CenterX, CenterY, (RingInnerLo + RingInnerHi) / 2, midAngle);

            var stack = new StackPanel { HorizontalAlignment = HAlign.Center };
            stack.Children.Add(new TextBlock
            {
                Text = s.Label,
                FontSize = 9,
                FontWeight = FontWeights.Bold,
                Foreground = ParseHex(s.Color),
                HorizontalAlignment = HAlign.Center,
            });
            stack.Children.Add(new TextBlock
            {
                Text = $"{s.Value}/10",
                FontSize = 13,
                FontWeight = FontWeights.Bold,
                Foreground = ParseHex("#EDEDED"),
                HorizontalAlignment = HAlign.Center,
            });
            stack.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
            Canvas.SetLeft(stack, lx - stack.DesiredSize.Width / 2);
            Canvas.SetTop(stack, ly - stack.DesiredSize.Height / 2);
            DiagramCanvas.Children.Add(stack);

            cursor = endAngle;
        }
    }

    // ─────────────────── Draw: centre badge ───────────────────

    private void DrawCenterBadge()
    {
        var score = _focus?.Candidate?.Score ?? _focus?.Phantom?.Score;
        var (bg, fg) = score?.Severity switch
        {
            "Critical" => ("#22FF5B4F", "#FF5B4F"),
            "High"     => ("#22F5A524", "#F5A524"),
            "Medium"   => ("#220A72EF", "#0A72EF"),
            "Low"      => ("#2200CA4E", "#00CA4E"),
            _          => ("#22737373", "#737373"),
        };

        var disc = new Shapes.Ellipse
        {
            Width = RingCenter * 2,
            Height = RingCenter * 2,
            Fill = ParseHex(bg),
            Stroke = ParseHex(fg),
            StrokeThickness = 2,
        };
        disc.Effect = new System.Windows.Media.Effects.DropShadowEffect
        {
            Color = (Color)ColorConverter.ConvertFromString(fg),
            BlurRadius = 18,
            ShadowDepth = 0,
            Opacity = 0.55,
        };
        Canvas.SetLeft(disc, CenterX - RingCenter);
        Canvas.SetTop(disc, CenterY - RingCenter);
        DiagramCanvas.Children.Add(disc);

        var stack = new StackPanel { HorizontalAlignment = HAlign.Center };
        stack.Children.Add(new TextBlock
        {
            Text = score != null ? $"{score.Total}" : "—",
            FontSize = 30,
            FontWeight = FontWeights.Bold,
            Foreground = ParseHex(fg),
            HorizontalAlignment = HAlign.Center,
        });
        stack.Children.Add(new TextBlock
        {
            Text = score?.Severity.ToUpperInvariant() ?? "DEGRADED",
            FontSize = 9,
            FontWeight = FontWeights.Bold,
            Foreground = ParseHex(fg),
            HorizontalAlignment = HAlign.Center,
            Margin = new Thickness(0, -4, 0, 0),
        });
        stack.Children.Add(new TextBlock
        {
            Text = TruncateMid(_focus?.DllName ?? "?", 18),
            FontFamily = (FontFamily)FindResource("FontMono"),
            FontSize = 9,
            Foreground = ParseHex("#A1A1A1"),
            HorizontalAlignment = HAlign.Center,
            Margin = new Thickness(0, 4, 0, 0),
        });
        stack.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
        Canvas.SetLeft(stack, CenterX - stack.DesiredSize.Width / 2);
        Canvas.SetTop(stack, CenterY - stack.DesiredSize.Height / 2);
        DiagramCanvas.Children.Add(stack);
    }

    private static string TruncateMid(string s, int max)
    {
        if (string.IsNullOrEmpty(s) || s.Length <= max) return s;
        var keep = max - 1;
        var head = keep / 2;
        var tail = keep - head;
        return s[..head] + "…" + s[^tail..];
    }

    // ─────────────────── Draw: chain step nodes (middle ring) ───────────────────

    private void DrawChainNodes()
    {
        var priv = _focus?.Candidate?.Privesc ?? _focus?.Phantom?.Privesc;
        var steps = priv?.ChainSteps;

        var slots = new[]
        {
            (Kind: ChainStepKind.WritePrimitive,  Angle:   0.0, Label: "WRITE",    Color: "#F9E2AF"),
            (Kind: ChainStepKind.LoadVector,      Angle:  72.0, Label: "LOAD",     Color: "#0A72EF"),
            (Kind: ChainStepKind.Trigger,         Angle: 144.0, Label: "TRIGGER",  Color: "#CBA6F7"),
            (Kind: ChainStepKind.Privilege,       Angle: 216.0, Label: "PRIV",     Color: "#FF5B4F"),
            (Kind: ChainStepKind.RuntimeEvidence, Angle: 288.0, Label: "EVIDENCE", Color: "#00F0A3"),
        };

        foreach (var slot in slots)
        {
            var step = steps?.FirstOrDefault(s => s.Kind == slot.Kind);
            DrawChainNode(slot.Angle, slot.Label, slot.Color, step);
        }
    }

    private void DrawChainNode(double angleDeg, string kindLabel, string colorHex, ChainStep? step)
    {
        var (cx, cy) = Polar(CenterX, CenterY, RingMiddle, angleDeg);
        var hasContent = step != null;
        var color = ParseHex(colorHex);
        var dimColor = ParseHex(colorHex);
        dimColor.Opacity = 0.35;

        // Pill: kind label inside, label + detail outside (radially outward).
        var pill = new Border
        {
            CornerRadius = new CornerRadius(14),
            Padding = new Thickness(10, 4, 10, 4),
            Background = new SolidColorBrush(((SolidColorBrush)color).Color) { Opacity = hasContent ? 0.18 : 0.05 },
            BorderBrush = hasContent ? color : dimColor,
            BorderThickness = new Thickness(1.5),
        };
        if (hasContent)
        {
            pill.Effect = new System.Windows.Media.Effects.DropShadowEffect
            {
                Color = ((SolidColorBrush)color).Color,
                BlurRadius = 14,
                ShadowDepth = 0,
                Opacity = 0.5,
            };
        }
        var pillText = new TextBlock
        {
            Text = kindLabel,
            FontSize = 10,
            FontWeight = FontWeights.Bold,
            Foreground = hasContent ? color : dimColor,
        };
        pill.Child = pillText;
        pill.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
        Canvas.SetLeft(pill, cx - pill.DesiredSize.Width / 2);
        Canvas.SetTop(pill, cy - pill.DesiredSize.Height / 2);
        DiagramCanvas.Children.Add(pill);

        if (!hasContent)
        {
            // Ghost node — render a tiny "—" hint just outward of the pill so the user sees
            // the slot exists but no chain data is bound. Keep it discreet.
            var hint = new TextBlock
            {
                Text = "—",
                FontSize = 10,
                Foreground = ParseHex("#5A5A5A"),
            };
            var (hx, hy) = Polar(CenterX, CenterY, RingMiddle + 28, angleDeg);
            hint.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
            Canvas.SetLeft(hint, hx - hint.DesiredSize.Width / 2);
            Canvas.SetTop(hint, hy - hint.DesiredSize.Height / 2);
            DiagramCanvas.Children.Add(hint);
            return;
        }

        // Step Label + Detail rendered in a small panel positioned radially outward
        // from the pill. The panel hugs the centre line of the angle but is nudged
        // outward by ~36px so it doesn't overlap the pill itself.
        var detailPanel = new StackPanel { MaxWidth = 160 };
        detailPanel.Children.Add(new TextBlock
        {
            Text = step!.Label ?? "",
            FontSize = 11,
            FontWeight = FontWeights.SemiBold,
            Foreground = ParseHex("#EDEDED"),
            TextAlignment = TextAlignment.Center,
            TextWrapping = TextWrapping.Wrap,
        });
        if (!string.IsNullOrEmpty(step.Detail))
        {
            detailPanel.Children.Add(new TextBlock
            {
                Text = step.Detail,
                FontSize = 9,
                Foreground = ParseHex("#A1A1A1"),
                TextAlignment = TextAlignment.Center,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 1, 0, 0),
            });
        }
        var (dx, dy) = Polar(CenterX, CenterY, RingMiddle + 38, angleDeg);
        detailPanel.Measure(new Size(160, double.PositiveInfinity));
        Canvas.SetLeft(detailPanel, dx - detailPanel.DesiredSize.Width / 2);
        Canvas.SetTop(detailPanel, dy - detailPanel.DesiredSize.Height / 2);
        DiagramCanvas.Children.Add(detailPanel);
    }

    // ─────────────────── Draw: Bezier connectors ───────────────────

    /// <summary>
    /// Subtle Bezier flows from each outer card to the chain step it primarily
    /// feeds. Mapping:
    ///   DISCOVERY → centre badge (meta layer: how the candidate showed up)
    ///   STATIC    → WRITE + LOAD
    ///   DYNAMIC   → EVIDENCE
    ///   PRIVESC   → TRIGGER + PRIV
    /// Connectors that have no backing data (e.g. PRIVESC card empty) are
    /// rendered at lower opacity so the user sees the slot but reads it as
    /// "nothing to flow yet".
    /// </summary>
    private void DrawConnectors()
    {
        var priv = _focus?.Candidate?.Privesc ?? _focus?.Phantom?.Privesc;
        var hasPrivesc = priv != null && priv.Findings.Count > 0;
        var ev = _focus?.Candidate?.Evidence ?? _focus?.Phantom?.Evidence;
        var hasDynamic = ev != null || _focus?.Source == MainWindow.AttackFocusSource.RuntimeTrace;
        var hasStatic = _focus?.Candidate != null || _focus?.Phantom != null;

        // Card anchor points — edge of card facing the centre.
        var pDiscovery = new Point(CenterX, 108);   // bottom-centre of N card
        var pStatic    = new Point(720, CenterY);   // left-centre of E card
        var pDynamic   = new Point(CenterX, 596);   // top-centre of S card
        var pPrivesc   = new Point(180, CenterY);   // right-centre of W card

        // Chain step positions on the middle ring.
        var write    = PolarPoint(0,   RingMiddle);
        var load     = PolarPoint(72,  RingMiddle);
        var trigger  = PolarPoint(144, RingMiddle);
        var priv2    = PolarPoint(216, RingMiddle);
        var evidence = PolarPoint(288, RingMiddle);
        var center   = new Point(CenterX, CenterY);

        DrawBezier(pDiscovery, center,   "#00F0A3", active: true);                  // discovery → candidate centre
        DrawBezier(pStatic,    write,    "#0A72EF", active: hasStatic);             // static → WRITE
        DrawBezier(pStatic,    load,     "#0A72EF", active: hasStatic);             // static → LOAD
        DrawBezier(pDynamic,   evidence, "#F9E2AF", active: hasDynamic);            // dynamic → EVIDENCE
        DrawBezier(pPrivesc,   trigger,  "#FF5B4F", active: hasPrivesc);            // privesc → TRIGGER
        DrawBezier(pPrivesc,   priv2,    "#FF5B4F", active: hasPrivesc);            // privesc → PRIV
    }

    private Point PolarPoint(double angleDeg, double radius)
    {
        var (x, y) = Polar(CenterX, CenterY, radius, angleDeg);
        return new Point(x, y);
    }

    /// <summary>
    /// Cubic Bezier between two anchors with control points pulled ~30% of the way
    /// toward the diagram centre. Active connectors render at higher opacity and
    /// glow; inactive ones are dim enough to read as "slot exists, no flow".
    /// </summary>
    private void DrawBezier(Point from, Point to, string colorHex, bool active)
    {
        var center = new Point(CenterX, CenterY);
        var c1 = LerpToward(from, center, 0.35);
        var c2 = LerpToward(to,   center, 0.35);

        var fig = new PathFigure { StartPoint = from, IsClosed = false };
        fig.Segments.Add(new BezierSegment(c1, c2, to, true));

        var path = new Shapes.Path
        {
            Data = new PathGeometry { Figures = { fig } },
            Stroke = ParseHex(colorHex),
            StrokeThickness = active ? 1.5 : 0.8,
            Opacity = active ? 0.55 : 0.18,
            StrokeDashArray = active ? null : new DoubleCollection(new[] { 4.0, 3.0 }),
            IsHitTestVisible = false,
        };
        if (active)
        {
            path.Effect = new System.Windows.Media.Effects.DropShadowEffect
            {
                Color = (Color)ColorConverter.ConvertFromString(colorHex),
                BlurRadius = 8,
                ShadowDepth = 0,
                Opacity = 0.45,
            };
        }
        DiagramCanvas.Children.Add(path);
    }

    private static Point LerpToward(Point from, Point target, double t) =>
        new Point(from.X + (target.X - from.X) * t, from.Y + (target.Y - from.Y) * t);

    // ─────────────────── Draw: outer cards (compass) ───────────────────

    private void DrawOuterCards()
    {
        // North = Discovery, East = Static, South = Dynamic, West = Privesc.
        DrawOuterCard("DISCOVERY", "#00F0A3", BuildDiscoveryItems(),
            x: CenterX - 130, y: 12, w: 260, h: 96);
        DrawOuterCard("STATIC", "#0A72EF", BuildStaticItems(),
            x: 720, y: CenterY - 70, w: 168, h: 140);
        DrawOuterCard("DYNAMIC", "#F9E2AF", BuildDynamicItems(),
            x: CenterX - 130, y: 596, w: 260, h: 96);
        DrawOuterCard("PRIVESC", "#FF5B4F", BuildPrivescItems(),
            x: 12, y: CenterY - 70, w: 168, h: 140);
    }

    private void DrawOuterCard(string title, string colorHex, IEnumerable<string> items,
        double x, double y, double w, double h)
    {
        var color = ParseHex(colorHex);
        var card = new Border
        {
            Width = w,
            Height = h,
            CornerRadius = new CornerRadius(8),
            Background = ParseHex("#191919"),
            BorderBrush = color,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(10, 8, 10, 8),
        };
        card.Effect = new System.Windows.Media.Effects.DropShadowEffect
        {
            Color = ((SolidColorBrush)color).Color,
            BlurRadius = 10,
            ShadowDepth = 0,
            Opacity = 0.18,
        };

        var stack = new StackPanel();
        stack.Children.Add(new TextBlock
        {
            Text = title,
            FontSize = 10,
            FontWeight = FontWeights.Bold,
            Foreground = color,
            Margin = new Thickness(0, 0, 0, 4),
        });

        foreach (var item in items.Take(4))
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
        var total = items.Count();
        if (total > 4)
        {
            stack.Children.Add(new TextBlock
            {
                Text = $"+{total - 4} more",
                FontSize = 10,
                Foreground = ParseHex("#737373"),
                Margin = new Thickness(8, 1, 0, 0),
            });
        }
        else if (total == 0)
        {
            stack.Children.Add(new TextBlock
            {
                Text = "(no signals)",
                FontSize = 11,
                FontStyle = FontStyles.Italic,
                Foreground = ParseHex("#737373"),
            });
        }

        card.Child = stack;
        Canvas.SetLeft(card, x);
        Canvas.SetTop(card, y);
        DiagramCanvas.Children.Add(card);
    }

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

    // ─────────────────── Empty-state nav ───────────────────

    private void GoScan_Click(object sender, RoutedEventArgs e) =>
        _main.NavigateTo(new ScanPage(_main));

    private void GoRuntime_Click(object sender, RoutedEventArgs e) =>
        _main.NavigateTo(new RuntimeTracePage(_main));
}
