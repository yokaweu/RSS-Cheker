using RSSChecker.Models;

namespace RSSChecker.Scanning;

public sealed class GameIntegrityScanner : IScanner
{
    public string Name => "CS2 integrity";

    public async Task ScanAsync(ScanContext c, CancellationToken ct)
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var drive in DriveInfo.GetDrives().Where(x => x.IsReady))
        {
            string steam = Path.Combine(drive.RootDirectory.FullName, "Program Files (x86)", "Steam");
            if (Directory.Exists(steam)) roots.Add(steam);
            steam = Path.Combine(drive.RootDirectory.FullName, "Steam");
            if (Directory.Exists(steam)) roots.Add(steam);
        }

        foreach (var root in roots)
        {
            var common = Path.Combine(root, "steamapps", "common", "Counter-Strike Global Offensive");
            if (!Directory.Exists(common)) continue;

            c.Report.Notes.Add($"Найдена установка CS2: {common}.");

            var files = Directory.EnumerateFiles(common, "*", SearchOption.AllDirectories)
                .Where(x =>
                {
                    string ext = Path.GetExtension(x);
                    return ext.Equals(".asi", StringComparison.OrdinalIgnoreCase) ||
                           (c.HasDatabase && (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                                              ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)));
                })
                .Take(10000);

            foreach (var f in files)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    c.Checked();
                    if (c.HasDatabase)
                    {
                        string hash = await FileAnalysis.ComputeHashAsync(f, ct);
                        if (c.KnownByHash.TryGetValue(hash, out var hit))
                        {
                            FileAnalysis.ReportKnownHash(c, f, hit, hash, "Файлы CS2 + SHA-256");
                            continue;
                        }
                    }

                    if (Path.GetExtension(f).Equals(".asi", StringComparison.OrdinalIgnoreCase))
                    {
                        var trust = TrustEvaluator.Verify(f);
                        if (trust.IsTrustedPublisher) continue;

                        string hash = await FileAnalysis.ComputeHashAsync(f, ct);
                        c.ReportEvidence(
                            name: Path.GetFileName(f),
                            path: f,
                            category: "Плагин игры (.asi)",
                            evidence: new EvidenceItem
                            {
                                SourceType = "Папка игры CS2",
                                Description = "Обнаружен сторонний ASI-плагин внутри папки игры.",
                                PathOrKey = f,
                                ScoreContribution = 25,
                                ObservedAt = File.GetLastWriteTimeUtc(f)
                            },
                            sha256: hash);
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }
}
