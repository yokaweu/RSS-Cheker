using Microsoft.Win32;
using RSSChecker.Models;

namespace RSSChecker.Scanning;

public sealed class PersistenceScanner : IScanner
{
    public string Name => "Persistence";

    public Task ScanAsync(ScanContext c, CancellationToken ct)
    {
        foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
        {
            foreach (var sub in new[]
            {
                @"Software\Microsoft\Windows\CurrentVersion\Run",
                @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
            })
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var k = hive.OpenSubKey(sub);
                    if (k == null) continue;

                    foreach (var n in k.GetValueNames())
                    {
                        c.Checked();
                        string v = k.GetValue(n)?.ToString() ?? "";
                        if (string.IsNullOrWhiteSpace(v)) continue;

                        string path = ExtractExecutablePath(v);
                        if (string.IsNullOrWhiteSpace(path)) continue;

                        // Verify signature if file exists — skip trusted Microsoft/vendor startup items
                        // like SecurityHealthSystray.exe!
                        if (File.Exists(path))
                        {
                            var trust = TrustEvaluator.Verify(path);
                            if (trust.IsTrustedPublisher)
                                continue;
                        }

                        if (CheatCatalog.TryMatchSpecificTool(path, out var sig) && sig != null)
                        {
                            c.ReportEvidence(
                                name: Path.GetFileName(path),
                                path: path,
                                category: sig.Category,
                                evidence: new EvidenceItem
                                {
                                    SourceType = "Автозагрузка (реестр)",
                                    Description = $"Запись автозагрузки ({sub}) указывает на «{sig.ToolName}».",
                                    PathOrKey = $@"{hive.Name}\{sub}\{n}",
                                    ScoreContribution = 25
                                },
                                detectedTool: sig.ToolName);
                        }
                        else if (IsUserWritableLocation(path))
                        {
                            // Unsigned startup entry in user-writable path -> weak signal (Unverified, NOT Suspicious)
                            c.ReportEvidence(
                                name: Path.GetFileName(path),
                                path: path,
                                category: "Автозагрузка",
                                evidence: new EvidenceItem
                                {
                                    SourceType = "Автозагрузка (реестр)",
                                    Description = $"Неподписанная программа в автозагрузке ({sub}). Само по себе не является угрозой.",
                                    PathOrKey = $@"{hive.Name}\{sub}\{n}",
                                    ScoreContribution = 10
                                });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }

        // Check Services pointing to user-writable paths (unsigned only)
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (key != null)
            {
                foreach (var n in key.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var s = key.OpenSubKey(n);
                        string image = s?.GetValue("ImagePath")?.ToString() ?? "";
                        if (string.IsNullOrWhiteSpace(image)) continue;

                        string path = ExtractExecutablePath(Environment.ExpandEnvironmentVariables(image));
                        if (!IsUserWritableLocation(path)) continue;

                        if (File.Exists(path) && TrustEvaluator.Verify(path).IsTrustedPublisher)
                            continue;

                        c.ReportEvidence(
                            name: Path.GetFileName(path),
                            path: path,
                            category: "Служба Windows",
                            evidence: new EvidenceItem
                            {
                                SourceType = "Служба (реестр)",
                                Description = "Служба запускает неподписанный файл из пользовательской папки.",
                                PathOrKey = $@"HKLM\SYSTEM\CurrentControlSet\Services\{n}",
                                ScoreContribution = 15
                            });
                    }
                    catch { }
                }
            }
        }
        catch { }

        return Task.CompletedTask;
    }

    static string ExtractExecutablePath(string commandLine)
    {
        string trimmed = commandLine.Trim();
        if (trimmed.StartsWith('"'))
        {
            int end = trimmed.IndexOf('"', 1);
            if (end > 1) return trimmed[1..end];
        }

        int exeIdx = trimmed.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIdx > 0) return trimmed[..(exeIdx + 4)];

        int dllIdx = trimmed.IndexOf(".dll", StringComparison.OrdinalIgnoreCase);
        if (dllIdx > 0) return trimmed[..(dllIdx + 4)];

        return "";
    }

    static bool IsUserWritableLocation(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        return path.Contains(@"\Users\", StringComparison.OrdinalIgnoreCase) ||
               path.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
               path.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase);
    }
}
