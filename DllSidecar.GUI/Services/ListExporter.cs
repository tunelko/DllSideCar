using System.IO;
using System.Text;
using System.Windows;
using Microsoft.Win32;

namespace DllSidecar.GUI.Services;

/// <summary>Clipboard / file export for DLL lists; values are RFC-4180-lite escaped.</summary>
public static class ListExporter
{
    /// <summary>Copy rows to clipboard as TSV (tab-separated).</summary>
    public static bool CopyTsv(string[] header, IReadOnlyList<string[]> rows, out int copied)
    {
        copied = 0;
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine(string.Join("\t", header.Select(EscapeTsv)));
            foreach (var r in rows)
            {
                sb.AppendLine(string.Join("\t", r.Select(EscapeTsv)));
                copied++;
            }
            System.Windows.Clipboard.SetText(sb.ToString());
            return true;
        }
        catch { return false; }
    }

    /// <summary>Save rows via SaveFileDialog; returns the chosen path or null on cancel/error.</summary>
    public static string? SaveCsv(string[] header, IReadOnlyList<string[]> rows, string suggestedName)
    {
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "CSV (comma-separated)|*.csv|TSV (tab-separated)|*.tsv|Text file|*.txt",
            FileName = suggestedName,
            DefaultExt = ".csv",
            OverwritePrompt = true,
        };
        if (dlg.ShowDialog() != true) return null;

        var delim = Path.GetExtension(dlg.FileName).Equals(".tsv", StringComparison.OrdinalIgnoreCase) ? '\t' : ',';
        try
        {
            var sb = new StringBuilder();
            // UTF-8 BOM helps Excel auto-detect encoding.
            sb.Append(string.Join(delim, header.Select(h => EscapeCsv(h, delim))));
            sb.Append("\r\n");
            foreach (var r in rows)
            {
                sb.Append(string.Join(delim, r.Select(v => EscapeCsv(v, delim))));
                sb.Append("\r\n");
            }
            File.WriteAllText(dlg.FileName, sb.ToString(), new UTF8Encoding(true));
            return dlg.FileName;
        }
        catch { return null; }
    }

    private static string EscapeTsv(string v)
    {
        if (string.IsNullOrEmpty(v)) return "";
        return v.Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');
    }

    private static string EscapeCsv(string v, char delim)
    {
        if (string.IsNullOrEmpty(v)) return "";
        bool mustQuote = v.IndexOf(delim) >= 0 || v.IndexOf('"') >= 0 || v.IndexOf('\n') >= 0 || v.IndexOf('\r') >= 0;
        if (!mustQuote) return v;
        return "\"" + v.Replace("\"", "\"\"") + "\"";
    }
}
