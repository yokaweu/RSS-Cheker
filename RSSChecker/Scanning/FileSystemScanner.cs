using RSSChecker.Models;

namespace RSSChecker.Scanning;

public sealed class FileSystemScanner(bool full, IReadOnlyList<string>? exclusions = null, string sensitivity = "Balanced") : IScanner
{
    public string Name => "File system";

    static readonly string[] SkipDriveFolders =
    [
        "Windows", "Program Files", "Program Files (x86)", "$Recycle.Bin",
        "System Volume Information", "Recovery", "PerfLogs", "MSOCache"
    ];

    public async Task ScanAsync(ScanContext c, CancellationToken ct)
    {
        var userRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string u = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        foreach (var p in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(u, "Downloads"),
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
            appData,
            localAppData
        })
        {
            if (Directory.Exists(p)) userRoots.Add(p);
        }

        var driveRoots = new List<string>();
        foreach (var d in DriveInfo.GetDrives().Where(x => x.IsReady && x.DriveType == DriveType.Fixed))
        {
            driveRoots.Add(d.RootDirectory.FullName);
            if (full)
            {
                foreach (var p in new[]
                {
                    Path.Combine(d.RootDirectory.FullName, "Users"),
                    Path.Combine(d.RootDirectory.FullName, "ProgramData"),
                    Path.Combine(d.RootDirectory.FullName, "Games")
                })
                {
                    if (Directory.Exists(p)) userRoots.Add(p);
                }
            }
        }

        int maxDepth = full ? int.MaxValue : 2;
        int maxFiles = full ? int.MaxValue : 3000;
        var candidates = new List<string>(full ? 1024 : 512);

        void CollectFromRoot(string root, int depthLimit, bool skipSystemTopDirs)
        {
            var stack = new Stack<(string Dir, int Depth)>();
            stack.Push((root, 0));

            while (stack.Count > 0 && candidates.Count < maxFiles)
            {
                ct.ThrowIfCancellationRequested();
                var (dir, depth) = stack.Pop();
                if (IsExcluded(dir)) continue;

                try
                {
                    if (depth < depthLimit)
                    {
                        foreach (var sub in Directory.EnumerateDirectories(dir))
                        {
                            try
                            {
                                string subName = Path.GetFileName(sub);
                                if (skipSystemTopDirs && depth == 0 &&
                                    SkipDriveFolders.Contains(subName, StringComparer.OrdinalIgnoreCase))
                                    continue;

                                if (subName.Equals("Microsoft", StringComparison.OrdinalIgnoreCase) && !full)
                                    continue;

                                var a = File.GetAttributes(sub);
                                if ((a & FileAttributes.ReparsePoint) == 0 && !IsExcluded(sub))
                                    stack.Push((sub, depth + 1));

                                // Check folder name for specific known cheat tools (not generic words like "helper")
                                if (CheatCatalog.TryMatchSpecificTool(subName, out var dirSig) && dirSig != null)
                                {
                                    c.Checked();
                                    c.ReportEvidence(
                                        name: subName,
                                        path: sub,
                                        category: dirSig.Category,
                                        evidence: new EvidenceItem
                                        {
                                            SourceType = "Папка на диске",
                                            Description = $"Название папки совпадает с известным инструментом «{dirSig.ToolName}».",
                                            PathOrKey = sub,
                                            ScoreContribution = 35,
                                            ObservedAt = Directory.GetLastWriteTimeUtc(sub)
                                        },
                                        detectedTool: dirSig.ToolName);
                                }
                            }
                            catch { }
                        }
                    }

                    foreach (var f in Directory.EnumerateFiles(dir))
                    {
                        string ext = Path.GetExtension(f);
                        string fileName = Path.GetFileName(f);

                        if (IsInspectableExtension(ext))
                        {
                            if (CheatCatalog.TryMatchSpecificTool(fileName, out var fileSig) && fileSig != null)
                            {
                                var trust = TrustEvaluator.Verify(f);
                                if (!trust.IsTrustedPublisher)
                                {
                                    c.Checked();
                                    string hash = File.Exists(f) && new FileInfo(f).Length < 50_000_000
                                        ? FileAnalysis.ComputeHashAsync(f, ct).GetAwaiter().GetResult()
                                        : "";
                                    c.ReportEvidence(
                                        name: fileName,
                                        path: f,
                                        category: fileSig.Category,
                                        evidence: new EvidenceItem
                                        {
                                            SourceType = "Файл на диске",
                                            Description = $"Файл совпадает с известным инструментом «{fileSig.ToolName}».",
                                            PathOrKey = f,
                                            ScoreContribution = fileSig.BaseScore,
                                            ObservedAt = File.GetLastWriteTimeUtc(f)
                                        },
                                        sha256: hash,
                                        detectedTool: fileSig.ToolName);
                                }
                            }
                            else if (CheatCatalog.IsWeakGenericMatch(fileName, out var weakToken))
                            {
                                // Weak generic keyword ("loader", "injector", "helper"):
                                // Check signature first! If trusted (e.g. EasyAntiCheat_EOS_Setup.exe), ignore.
                                var trust = TrustEvaluator.Verify(f);
                                if (!trust.IsTrustedPublisher)
                                {
                                    c.Checked();
                                    c.ReportEvidence(
                                        name: fileName,
                                        path: f,
                                        category: "Непроверенный файл",
                                        evidence: new EvidenceItem
                                        {
                                            SourceType = "Файл на диске (имя)",
                                            Description = $"Имя файла содержит общее слово «{weakToken}», но не подтверждено как чит.",
                                            PathOrKey = f,
                                            ScoreContribution = 8,
                                            ObservedAt = File.GetLastWriteTimeUtc(f)
                                        });
                                }
                            }
                        }

                        if (IsBinaryCandidate(ext))
                        {
                            candidates.Add(f);
                            if (candidates.Count >= maxFiles) break;
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }

        foreach (var root in userRoots)
        {
            ct.ThrowIfCancellationRequested();
            CollectFromRoot(root, maxDepth, false);
        }

        foreach (var drv in driveRoots)
        {
            ct.ThrowIfCancellationRequested();
            CollectFromRoot(drv, full ? 4 : 2, true);
        }

        var options = new ParallelOptions
        {
            MaxDegreeOfParallelism = Math.Max(2, Environment.ProcessorCount),
            CancellationToken = ct
        };

        await Parallel.ForEachAsync(candidates, options, async (f, token) =>
        {
            try
            {
                var info = new FileInfo(f);
                if (!info.Exists || info.Length <= 0 || info.Length >= 20_000_000)
                    return;

                c.Checked();

                if (c.HasDatabase)
                {
                    string hash = await FileAnalysis.ComputeHashAsync(f, token);
                    if (c.KnownByHash.TryGetValue(hash, out var known))
                    {
                        FileAnalysis.ReportKnownHash(c, f, known, hash, "Файл на диске + SHA-256");
                        return;
                    }
                }

                // Skip static text heuristic for validly signed trusted publishers
                var trust = TrustEvaluator.Verify(f);
                if (trust.IsTrustedPublisher)
                    return;

                // Read up to 64 KB for static cheat signature tokens
                string text = "";
                try
                {
                    using var stream = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 16384, useAsync: true);
                    using var reader = new StreamReader(stream);
                    int toRead = (int)Math.Min(65_536, info.Length);
                    char[] b = new char[toRead];
                    int n = await reader.ReadAsync(b.AsMemory(), token);
                    text = new string(b, 0, n);
                }
                catch { }

                if (text.Length > 0)
                {
                    var hits = CheatCatalog.CheatContentTokens
                        .Where(w => text.Contains(w, StringComparison.OrdinalIgnoreCase))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToArray();

                    if (hits.Length >= 2 || (hits.Length == 1 && !trust.IsValidSignature))
                    {
                        string hash = await FileAnalysis.ComputeHashAsync(f, token);
                        int score = hits.Length >= 2 ? 40 : 15;
                        c.ReportEvidence(
                            name: Path.GetFileName(f),
                            path: f,
                            category: "Анализ содержимого",
                            evidence: new EvidenceItem
                            {
                                SourceType = "Сигнатуры в файле",
                                Description = $"Внутри файла найдены характерные строки: {string.Join(", ", hits)}.",
                                PathOrKey = f,
                                ScoreContribution = score,
                                ObservedAt = info.LastWriteTimeUtc
                            },
                            sha256: hash);
                    }
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        });
    }

    bool IsExcluded(string p) => exclusions?.Any(x =>
    {
        if (string.IsNullOrWhiteSpace(x)) return false;
        string root = Environment.ExpandEnvironmentVariables(x.Trim()).TrimEnd('\\', '/');
        return p.Equals(root, StringComparison.OrdinalIgnoreCase) ||
               p.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }) == true;

    bool IsBinaryCandidate(string e) =>
        e.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
        e.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
        e.Equals(".sys", StringComparison.OrdinalIgnoreCase) ||
        (sensitivity == "High" && (e.Equals(".scr", StringComparison.OrdinalIgnoreCase) ||
                                   e.Equals(".com", StringComparison.OrdinalIgnoreCase)));

    static bool IsInspectableExtension(string e) =>
        e.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
        e.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
        e.Equals(".sys", StringComparison.OrdinalIgnoreCase) ||
        e.Equals(".asi", StringComparison.OrdinalIgnoreCase) ||
        e.Equals(".zip", StringComparison.OrdinalIgnoreCase) ||
        e.Equals(".rar", StringComparison.OrdinalIgnoreCase) ||
        e.Equals(".7z", StringComparison.OrdinalIgnoreCase);
}
