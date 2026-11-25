using System.Diagnostics;
using RSSChecker.Models;

namespace RSSChecker.Scanning;

public sealed class ProcessScanner(IReadOnlyList<string>? exclusions = null) : IScanner
{
    public string Name => "Processes";

    public async Task ScanAsync(ScanContext c, CancellationToken ct)
    {
        foreach (var p in Process.GetProcesses())
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using (p)
                {
                    var path = p.MainModule?.FileName;
                    if (string.IsNullOrWhiteSpace(path) || !File.Exists(path) || IsExcluded(path))
                        continue;

                    c.Checked();

                    var trust = TrustEvaluator.Verify(path);

                    if (c.HasDatabase)
                    {
                        string hash = await FileAnalysis.ComputeHashAsync(path, ct);
                        if (c.KnownByHash.TryGetValue(hash, out var exact))
                        {
                            FileAnalysis.ReportKnownHash(c, path, exact, hash, "Процесс + SHA-256");
                            continue;
                        }
                    }

                    if (!trust.IsTrustedPublisher && CheatCatalog.TryMatchSpecificTool(path, out var sig) && sig != null)
                    {
                        c.ReportEvidence(
                            name: Path.GetFileName(path),
                            path: path,
                            category: sig.Category,
                            evidence: new EvidenceItem
                            {
                                SourceType = "Активный процесс",
                                Description = $"Запущенный процесс (PID {p.Id}) совпадает с сигнатурой «{sig.ToolName}».",
                                PathOrKey = $"{path} (PID {p.Id})",
                                ScoreContribution = sig.BaseScore,
                                ObservedAt = DateTimeOffset.Now
                            },
                            detectedTool: sig.ToolName);
                    }

                    if (p.ProcessName.Contains("cs2", StringComparison.OrdinalIgnoreCase))
                    {
                        c.Report.Notes.Add($"Обнаружен процесс CS2 (PID {p.Id}): {path}.");
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (System.ComponentModel.Win32Exception) { }
            catch (InvalidOperationException) { }
        }
    }

    bool IsExcluded(string path) => exclusions?.Any(x =>
        !string.IsNullOrWhiteSpace(x) &&
        (path.Equals(Environment.ExpandEnvironmentVariables(x.Trim().TrimEnd('\\')), StringComparison.OrdinalIgnoreCase) ||
         path.StartsWith(Environment.ExpandEnvironmentVariables(x.Trim().TrimEnd('\\')) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))) == true;
}
