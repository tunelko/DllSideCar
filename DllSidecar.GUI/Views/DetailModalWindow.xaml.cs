using System.Windows;
using System.Windows.Controls;

namespace DllSidecar.GUI.Views;

/// <summary>
/// Reusable modal that hosts any UIElement at 80% of the owning window's size.
/// Used by ScanPage / RuntimeTracePage to "expand" their inline details panels.
/// The caller detaches the child from its original parent, passes it in, and on
/// close re-attaches. We don't try to clone the visual tree; physical reparent
/// keeps all bindings, selection state and data intact.
/// </summary>
public partial class DetailModalWindow : Window
{
    private UIElement? _borrowed;

    public DetailModalWindow(string title, UIElement content, Window owner)
    {
        InitializeComponent();
        Owner = owner;
        TitleText.Text = title;
        Title = title;

        // Size to 80% of owner's actual bounds.
        if (owner.ActualWidth > 0 && owner.ActualHeight > 0)
        {
            Width  = owner.ActualWidth  * 0.8;
            Height = owner.ActualHeight * 0.8;
        }
        else
        {
            Width  = 1000;
            Height = 700;
        }

        _borrowed = content;
        Host.Content = content;
    }

    /// <summary>Detach the borrowed content before this window is closed so the caller can re-attach it.</summary>
    public UIElement? DetachContent()
    {
        var c = _borrowed;
        Host.Content = null;
        _borrowed = null;
        return c;
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
