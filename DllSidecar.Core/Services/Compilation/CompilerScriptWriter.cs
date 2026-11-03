using System.Text;
using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services.Compilation;

internal static class CompilerScriptWriter
{
    public static string Write(PeAnalysis pe, TemplateConfig config, string source, string mode)
    {
        var gnu = config.DInvoke || config.AnySyscalls || config.EncryptStrings || config.UnhookNtdll || config.PatchEtw
            || mode == "tracer" || (mode == "proxy" && !string.IsNullOrEmpty(config.TargetExport));
        var compiler = config.Compiler;
        if (compiler == CompilerKind.Auto)
            compiler = BuildSystem.FindGcc(pe.Arch) != null || gnu || MsvcBackend.FindVcVarsAll() == null
                ? CompilerKind.MinGW : CompilerKind.Msvc;
        var sb = new StringBuilder("@echo off\r\nsetlocal\r\ncd /d \"%~dp0\"\r\n");
        sb.AppendLine($"echo === DllSidecar {mode} Build: {compiler} / {pe.Arch} ===");
        if (compiler == CompilerKind.Msvc)
        {
            if (gnu)
            {
                sb.AppendLine("echo This template requires MinGW (GNU assembly or specialized headers).");
                sb.AppendLine("exit /b 1");
                return sb.ToString();
            }
            var configured = Configuration.ConfigManager.Current.Compiler.VcVarsAllPath;
            if (!string.IsNullOrWhiteSpace(configured) && configured.IndexOfAny(['"', '\r', '\n']) < 0)
                sb.AppendLine($"if not defined VCVARSALL set \"VCVARSALL={configured.Replace("%", "%%")}\"");
            sb.AppendLine("if defined VCVARSALL goto :vcvars_ready");
            sb.AppendLine("set \"VSWHERE=%ProgramFiles(x86)%\\Microsoft Visual Studio\\Installer\\vswhere.exe\"");
            sb.AppendLine("if not exist \"%VSWHERE%\" goto :msvc_missing");
            sb.AppendLine("for /f \"usebackq tokens=*\" %%I in (`\"%VSWHERE%\" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set \"VCVARSALL=%%I\\VC\\Auxiliary\\Build\\vcvarsall.bat\"");
            sb.AppendLine(":vcvars_ready");
            sb.AppendLine("if not exist \"%VCVARSALL%\" goto :msvc_missing");
            sb.AppendLine($"call \"%VCVARSALL%\" {pe.Arch} >nul");
            sb.AppendLine("if errorlevel 1 exit /b 1");
            sb.AppendLine("set \"RESOURCE=\"");
            sb.AppendLine("if not exist \"version.rc\" goto :compile_msvc");
            sb.AppendLine("rc /nologo /fo version.res version.rc");
            sb.AppendLine("if errorlevel 1 exit /b 1");
            sb.AppendLine("set \"RESOURCE=version.res\"");
            sb.AppendLine(":compile_msvc");
            var forwarder = mode == "proxy" && string.IsNullOrEmpty(config.TargetExport);
            var extraSource = forwarder ? $" \"{source}.msvc_exports.c\"" : "";
            var definition = source + (forwarder ? ".msvc.def" : ".def");
            sb.AppendLine($"cl /nologo /LD /MT /TC /utf-8 /D_CRT_SECURE_NO_WARNINGS /I. \"{source}.c\"{extraSource} /link /OUT:\"{pe.Filename}\" /DEF:\"{definition}\" /MACHINE:{(pe.Arch == "x86" ? "X86" : "X64")} %RESOURCE% user32.lib kernel32.lib advapi32.lib" +
                (config.Payload == PayloadType.ReverseShell ? " ws2_32.lib" : ""));
            sb.AppendLine("if errorlevel 1 exit /b 1");
            sb.AppendLine("goto :compiled");
            sb.AppendLine(":msvc_missing");
            sb.AppendLine("echo Visual Studio C++ tools missing. Install C++ workload + SDK or set VCVARSALL.");
            sb.AppendLine("exit /b 1");
        }
        else
        {
            var prefix = pe.Arch == "x86" ? "i686-w64-mingw32" : "x86_64-w64-mingw32";
            var gcc = BuildSystem.FindGcc(pe.Arch) ?? prefix + "-gcc.exe";
            if (Path.IsPathRooted(gcc)) sb.AppendLine($"set \"PATH={Path.GetDirectoryName(gcc)};%PATH%\"");
            var windres = BuildSystem.FindWindres(pe.Arch) ?? prefix + "-windres.exe";
            sb.AppendLine("set \"RESOURCE=\"");
            sb.AppendLine("if not exist \"version.rc\" goto :compile_mingw");
            sb.AppendLine($"\"{windres}\" \"version.rc\" -o \"version.res.o\"");
            sb.AppendLine("if errorlevel 1 exit /b 1");
            sb.AppendLine("set \"RESOURCE=version.res.o\"");
            sb.AppendLine(":compile_mingw");
            sb.AppendLine($"\"{gcc}\" -shared -O0 -I. -o \"{pe.Filename}\" \"{source}.c\" \"{source}.def\" %RESOURCE% -luser32 -lkernel32 -ladvapi32 -Wl,--kill-at" +
                (config.Payload == PayloadType.ReverseShell ? " -lws2_32" : ""));
            sb.AppendLine("if errorlevel 1 exit /b 1");
        }
        sb.AppendLine(":compiled");
        sb.AppendLine($"echo Built: {pe.Filename} ({pe.Arch})");
        return sb.ToString().ReplaceLineEndings("\r\n");
    }
}
