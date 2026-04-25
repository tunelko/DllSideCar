using System.Windows;
using System.Windows.Controls;
using DllSidecar.Core.Configuration;
using DllSidecar.Core.Helpers;

namespace DllSidecar.GUI.Views;

public partial class HashPage : Page
{
    private readonly MainWindow _main;

    public HashPage(MainWindow main)
    {
        _main = main;
        InitializeComponent();
        PopulateKeys();
    }

    private void PopulateKeys()
    {
        var cfg = ConfigManager.Current.Xor;
        XorKeyCombo.Items.Clear();
        foreach (var k in cfg.PresetKeys)
            XorKeyCombo.Items.Add($"0x{k:X2}");
        var idx = cfg.PresetKeys.IndexOf(cfg.DefaultKey);
        XorKeyCombo.SelectedIndex = idx >= 0 ? idx : 0;
    }

    private void Hash_Click(object sender, RoutedEventArgs e)
    {
        var input = InputBox.Text.Trim();
        if (string.IsNullOrEmpty(input)) return;

        var hcs = Djb2.Hash(input);
        var hci = Djb2.HashInsensitive(input);
        HashSensitive.Text   = $"djb2 (case-sensitive):   0x{hcs:X8}UL";
        HashInsensitive.Text = $"djb2 (case-insensitive): 0x{hci:X8}UL";

        var cfg = ConfigManager.Current.Xor;
        byte key = cfg.DefaultKey;
        if (XorKeyCombo.SelectedIndex >= 0 && XorKeyCombo.SelectedIndex < cfg.PresetKeys.Count)
            key = cfg.PresetKeys[XorKeyCombo.SelectedIndex];

        var enc = XorCryptor.Encrypt(input, key);
        XorResult.Text = $"XOR (key 0x{key:X2}): {{{XorCryptor.ToHexArray(enc)}}}";
    }
}
