using System.Windows;
using System.Windows.Media;

namespace DllSidecar.GUI.Views;

/// <summary>
/// Drop-in replacement for <see cref="MessageBox"/> with the app's dark theme.
/// Mirrors the static Show(...) overloads so callers can swap the type name and
/// keep the rest of the call site unchanged. The window itself is just a thin
/// chrome around a header (glyph + title), a body TextBlock, and a button strip
/// built dynamically from the requested <see cref="MessageBoxButton"/>.
/// </summary>
public partial class AppDialog : Window
{
    private MessageBoxResult _result = MessageBoxResult.None;

    private AppDialog() { InitializeComponent(); }

    // Title-strip close button. Sets result to Cancel (or None for OK-only dialogs)
    // so callers reading the result don't get a false-OK from clicking the X.
    private void Close_Click(object sender, RoutedEventArgs e)
    {
        if (_result == MessageBoxResult.None)
            _result = MessageBoxResult.Cancel;
        Close();
    }

    // ── Static API mirroring System.Windows.MessageBox.Show ────────────────

    public static MessageBoxResult Show(string text)
        => Show(null, text, "DllSidecar", MessageBoxButton.OK, MessageBoxImage.None, MessageBoxResult.OK);

    public static MessageBoxResult Show(string text, string caption)
        => Show(null, text, caption, MessageBoxButton.OK, MessageBoxImage.None, MessageBoxResult.OK);

    public static MessageBoxResult Show(string text, string caption, MessageBoxButton button)
        => Show(null, text, caption, button, MessageBoxImage.None, DefaultFor(button));

    public static MessageBoxResult Show(string text, string caption, MessageBoxButton button, MessageBoxImage icon)
        => Show(null, text, caption, button, icon, DefaultFor(button));

    public static MessageBoxResult Show(string text, string caption, MessageBoxButton button, MessageBoxImage icon, MessageBoxResult defaultResult)
        => Show(null, text, caption, button, icon, defaultResult);

    public static MessageBoxResult Show(Window? owner, string text)
        => Show(owner, text, "DllSidecar", MessageBoxButton.OK, MessageBoxImage.None, MessageBoxResult.OK);

    public static MessageBoxResult Show(Window? owner, string text, string caption)
        => Show(owner, text, caption, MessageBoxButton.OK, MessageBoxImage.None, MessageBoxResult.OK);

    public static MessageBoxResult Show(Window? owner, string text, string caption, MessageBoxButton button)
        => Show(owner, text, caption, button, MessageBoxImage.None, DefaultFor(button));

    public static MessageBoxResult Show(Window? owner, string text, string caption, MessageBoxButton button, MessageBoxImage icon)
        => Show(owner, text, caption, button, icon, DefaultFor(button));

    public static MessageBoxResult Show(Window? owner, string text, string caption, MessageBoxButton button, MessageBoxImage icon, MessageBoxResult defaultResult)
    {
        var dlg = new AppDialog
        {
            Title = caption,
            Owner = owner,
            WindowStartupLocation = owner != null ? WindowStartupLocation.CenterOwner : WindowStartupLocation.CenterScreen,
        };
        dlg.ChromeTitle.Text = string.IsNullOrWhiteSpace(caption) ? "DllSidecar" : caption;
        dlg.TitleText.Text = caption;
        dlg.BodyText.Text = text;
        ApplyIcon(dlg, icon);
        BuildButtons(dlg, button, defaultResult);
        dlg.ShowDialog();
        return dlg._result;
    }

    private static MessageBoxResult DefaultFor(MessageBoxButton button) => button switch
    {
        MessageBoxButton.OK => MessageBoxResult.OK,
        MessageBoxButton.OKCancel => MessageBoxResult.OK,
        MessageBoxButton.YesNo => MessageBoxResult.Yes,
        MessageBoxButton.YesNoCancel => MessageBoxResult.Yes,
        _ => MessageBoxResult.None,
    };

    // ── Header glyph (matches MessageBoxImage semantics) ───────────────────

    private static void ApplyIcon(AppDialog dlg, MessageBoxImage icon)
    {
        switch (icon)
        {
            case MessageBoxImage.Information:
                dlg.IconGlyph.Text = "ℹ";   // INFORMATION SOURCE
                dlg.IconGlyph.Foreground = new SolidColorBrush(Color.FromRgb(0x89, 0xB4, 0xFA));  // sapphire
                break;
            case MessageBoxImage.Question:
                dlg.IconGlyph.Text = "?";
                dlg.IconGlyph.Foreground = new SolidColorBrush(Color.FromRgb(0x89, 0xB4, 0xFA));
                break;
            case MessageBoxImage.Warning:
                dlg.IconGlyph.Text = "⚠";   // WARNING SIGN
                dlg.IconGlyph.Foreground = new SolidColorBrush(Color.FromRgb(0xF9, 0xE2, 0xAF));  // amber
                break;
            case MessageBoxImage.Error:
                dlg.IconGlyph.Text = "✕";   // MULTIPLICATION X
                dlg.IconGlyph.Foreground = new SolidColorBrush(Color.FromRgb(0xF3, 0x8B, 0xA8));  // red-pink
                break;
            default:
                dlg.IconGlyph.Visibility = Visibility.Collapsed;
                break;
        }
    }

    // ── Action strip (rightmost button is primary, matches Windows convention) ──

    private static void BuildButtons(AppDialog dlg, MessageBoxButton kind, MessageBoxResult defaultResult)
    {
        switch (kind)
        {
            case MessageBoxButton.OK:
                dlg.ButtonStrip.Children.Add(MakeButton(dlg, "OK", MessageBoxResult.OK,
                    isPrimary: true, isCancel: true, isDefault: defaultResult == MessageBoxResult.OK));
                break;
            case MessageBoxButton.OKCancel:
                dlg.ButtonStrip.Children.Add(MakeButton(dlg, "Cancel", MessageBoxResult.Cancel,
                    isPrimary: false, isCancel: true, isDefault: defaultResult == MessageBoxResult.Cancel));
                dlg.ButtonStrip.Children.Add(MakeButton(dlg, "OK", MessageBoxResult.OK,
                    isPrimary: true, isCancel: false, isDefault: defaultResult == MessageBoxResult.OK));
                break;
            case MessageBoxButton.YesNo:
                dlg.ButtonStrip.Children.Add(MakeButton(dlg, "No", MessageBoxResult.No,
                    isPrimary: false, isCancel: true, isDefault: defaultResult == MessageBoxResult.No));
                dlg.ButtonStrip.Children.Add(MakeButton(dlg, "Yes", MessageBoxResult.Yes,
                    isPrimary: true, isCancel: false, isDefault: defaultResult == MessageBoxResult.Yes));
                break;
            case MessageBoxButton.YesNoCancel:
                dlg.ButtonStrip.Children.Add(MakeButton(dlg, "Cancel", MessageBoxResult.Cancel,
                    isPrimary: false, isCancel: true, isDefault: defaultResult == MessageBoxResult.Cancel));
                dlg.ButtonStrip.Children.Add(MakeButton(dlg, "No", MessageBoxResult.No,
                    isPrimary: false, isCancel: false, isDefault: defaultResult == MessageBoxResult.No));
                dlg.ButtonStrip.Children.Add(MakeButton(dlg, "Yes", MessageBoxResult.Yes,
                    isPrimary: true, isCancel: false, isDefault: defaultResult == MessageBoxResult.Yes));
                break;
        }
    }

    private static System.Windows.Controls.Button MakeButton(
        AppDialog dlg, string label, MessageBoxResult result,
        bool isPrimary, bool isCancel, bool isDefault)
    {
        var styleKey = isPrimary ? "AccentButton" : "SecondaryButton";
        var btn = new System.Windows.Controls.Button
        {
            Content = label,
            Style = (Style)dlg.FindResource(styleKey),
            IsCancel = isCancel,
            IsDefault = isDefault,
            Margin = new Thickness(8, 0, 0, 0),
            MinWidth = 80,
        };
        btn.Click += (_, _) => { dlg._result = result; dlg.Close(); };
        return btn;
    }
}
