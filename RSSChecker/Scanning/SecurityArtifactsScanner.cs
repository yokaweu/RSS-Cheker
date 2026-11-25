using Microsoft.Win32;
using RSSChecker.Models;

namespace RSSChecker.Scanning;

public sealed class SecurityArtifactsScanner : IScanner
{
    public string Name => "Traces & artifacts";

    static readonly string[] LegitIgnoreTokens =
    [
        "EASYANTICHEAT", "BATTLEYE", "VANGUARD", "VGC.EXE", "VGK",
        "SECURITYHEALTH", "STEAM", "DISCORD", "NVIDIA", "CHROME", "EDGE"
    ];

    static bool IsKnownLegitKeyword(string name) =>
        LegitIgnoreTokens.Any(t => name.Contains(t, StringComparison.OrdinalIgnoreCase));

    public Task ScanAsync(ScanContext c, CancellationToken ct)
    {
        // 1. Windows Prefetch (*.pf) — traces of previously executed programs
        string prefetchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        try
        {
            if (Directory.Exists(prefetchDir))
            {
                foreach (var f in Directory.EnumerateFiles(prefetchDir, "*.pf").Take(2000))
                {
                    ct.ThrowIfCancellationRequested();
                    c.Checked();

                    string pfName = Path.GetFileName(f);
                    if (IsKnownLegitKeyword(pfName)) continue;

                    // Extract executable name from "EXAMPLE.EXE-1A2B3C4D.pf"
                    string exeName = ExtractPrefetchExeName(pfName);
                    DateTimeOffset? lastRun = null;
                    try { lastRun = File.GetLastWriteTimeUtc(f); } catch { }

                    if (CheatCatalog.TryMatchSpecificTool(exeName, out var sig) && sig != null)
                    {
                        c.ReportEvidence(
                            name: exeName,
                            path: f,
                            category: sig.Category,
                            evidence: new EvidenceItem
                            {
                                SourceType = "След запуска (Prefetch)",
                                Description = $"В Prefetch зафиксирован запуск «{sig.ToolName}» ({pfName}).",
                                PathOrKey = f,
                                ScoreContribution = 35,
                                ObservedAt = lastRun
                            },
                            detectedTool: sig.ToolName,
                            exeKeyForCorrelation: exeName);
                    }
                    else if (CheatCatalog.IsWeakGenericMatch(exeName, out var weakToken))
                    {
                        c.ReportEvidence(
                            name: exeName,
                            path: f,
                            category: "Следы запуска",
                            evidence: new EvidenceItem
                            {
                                SourceType = "След запуска (Prefetch)",
                                Description = $"В Prefetch есть запись с общим словом «{weakToken}» ({pfName}). Само по себе не доказывает наличие чита.",
                                PathOrKey = f,
                                ScoreContribution = 12,
                                ObservedAt = lastRun
                            },
                            exeKeyForCorrelation: exeName);
                    }
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            c.Report.Notes.Add("Prefetch недоступен без прав администратора.");
        }
        catch (IOException) { }

        // 2. Registry AppCompatFlags / MuiCache — traces of executed apps
        var regPaths = new[]
        {
            @"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
            @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
        };

        foreach (var sub in regPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(sub);
                if (key == null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    c.Checked();

                    if (IsKnownLegitKeyword(valueName)) continue;

                    string cleanPath = ExtractPathFromRegValue(valueName);
                    string fileName = !string.IsNullOrWhiteSpace(cleanPath) ? Path.GetFileName(cleanPath) : valueName;

                    // If the file exists on disk and has a valid trusted signature, skip it!
                    if (!string.IsNullOrWhiteSpace(cleanPath) && File.Exists(cleanPath))
                    {
                        var trust = TrustEvaluator.Verify(cleanPath);
                        if (trust.IsTrustedPublisher)
                            continue;
                    }

                    if (CheatCatalog.TryMatchSpecificTool(valueName, out var sig) && sig != null)
                    {
                        c.ReportEvidence(
                            name: fileName,
                            path: cleanPath,
                            category: sig.Category,
                            evidence: new EvidenceItem
                            {
                                SourceType = "След в реестре",
                                Description = $"В истории запуска (реестр) найден след «{sig.ToolName}».",
                                PathOrKey = $@"HKCU\{sub}\{fileName}",
                                ScoreContribution = 30
                            },
                            detectedTool: sig.ToolName,
                            exeKeyForCorrelation: fileName);
                    }
                    else if (CheatCatalog.IsWeakGenericMatch(fileName, out var weakToken))
                    {
                        c.ReportEvidence(
                            name: fileName,
                            path: cleanPath,
                            category: "Следы в реестре",
                            evidence: new EvidenceItem
                            {
                                SourceType = "След в реестре",
                                Description = $"В реестре найдена запись со словом «{weakToken}». Само по себе не доказывает наличие чита.",
                                PathOrKey = $@"HKCU\{sub}\{fileName}",
                                ScoreContribution = 10
                            },
                            exeKeyForCorrelation: fileName);
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.SecurityException) { }
        }

        return Task.CompletedTask;
    }

    static string ExtractPrefetchExeName(string pfFileName)
    {
        int dash = pfFileName.LastIndexOf('-');
        if (dash > 0) return pfFileName[..dash];
        return Path.GetFileNameWithoutExtension(pfFileName);
    }

    static string ExtractPathFromRegValue(string raw)
    {
        int exe = raw.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exe > 0) return raw[..(exe + 4)];
        return raw;
    }
}
