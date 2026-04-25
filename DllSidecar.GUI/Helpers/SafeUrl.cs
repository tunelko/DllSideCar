using System.Diagnostics;
using DllSidecar.Core.Logging;

namespace DllSidecar.GUI.Helpers;

/// <summary>
/// Safely opens a URL in the default browser. Blocks any scheme other than http/https to
/// prevent a malicious config file (or future feature) from passing arbitrary strings to
/// ShellExecute (which would launch file:// paths, ms-settings:, javascript:, etc).
/// </summary>
public static class SafeUrl
{
    public static bool Open(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            Log.Warn("url", "Refused to open empty URL");
            return false;
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            Log.Warn("url", $"Refused to open malformed URL: {url}");
            return false;
        }

        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
        {
            Log.Warn("url", $"Refused to open URL with unsupported scheme '{uri.Scheme}': {url}");
            return false;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = uri.AbsoluteUri,
                UseShellExecute = true,
            });
            return true;
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            Log.Warn("url", $"ShellExecute failed for {url}", ex);
            return false;
        }
        catch (Exception ex)
        {
            Log.Error("url", $"Unexpected error opening {url}", ex);
            return false;
        }
    }
}
