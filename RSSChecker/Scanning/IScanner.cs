using System.Security.Cryptography;
using RSSChecker.Models;

namespace RSSChecker.Scanning;

public sealed class ScanContext
{
    readonly object gate = new();
    int checkedCount;

    public ScanReport Report { get; }
    public ThreatDatabase Database { get; }
    public IProgress<(string Phase, int Percent)> Progress { get; }
    public Dictionary<string, ThreatEntry> KnownByHash { get; }
    public bool HasDatabase => KnownByHash.Count > 0;

    readonly Dictionary<string, Finding> byHash = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, Finding> byPath = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, Finding> byExeName = new(StringComparer.OrdinalIgnoreCase);

    public ScanContext(ScanReport report, ThreatDatabase db, IProgress<(string Phase, int Percent)> progress)
    {
        Report = report;
        Database = db;
        Progress = progress;
        KnownByHash = db.Entries
            .Where(e => !string.IsNullOrWhiteSpace(e.Sha256))
            .GroupBy(e => e.Sha256, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
    }

    public static string NormalizePath(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "";
        string trimmed = raw.Trim().Trim('"');
        try
        {
            return Path.GetFullPath(trimmed);
        }
        catch
        {
            return trimmed;
        }
    }

    public void ReportEvidence(
        string name,
        string path,
        string category,
        EvidenceItem evidence,
        string sha256 = "",
        string detectedTool = "",
        string? exeKeyForCorrelation = null)
    {
        string normPath = NormalizePath(path);
        string exeKey = exeKeyForCorrelation ?? ExtractExeKey(normPath, name);

        lock (gate)
        {
            Finding? target = null;

            if (!string.IsNullOrWhiteSpace(sha256) && byHash.TryGetValue(sha256, out var fHash))
                target = fHash;
            else if (!string.IsNullOrWhiteSpace(normPath) && byPath.TryGetValue(normPath, out var fPath))
                target = fPath;
            else if (!string.IsNullOrWhiteSpace(exeKey) && byExeName.TryGetValue(exeKey, out var fExe))
                target = fExe;

            if (target == null)
            {
                target = new Finding
                {
                    Name = string.IsNullOrWhiteSpace(name) ? Path.GetFileName(normPath) : name,
                    Path = normPath,
                    NormalizedKey = !string.IsNullOrWhiteSpace(normPath) ? normPath : exeKey,
                    Category = category,
                    Sha256 = sha256,
                    DetectedTool = detectedTool
                };

                if (!string.IsNullOrWhiteSpace(normPath) && File.Exists(normPath))
                {
                    var trust = TrustEvaluator.Verify(normPath);
                    target.IsSigned = trust.IsValidSignature;
                    target.IsTrustedPublisher = trust.IsTrustedPublisher;
                    target.Publisher = trust.Publisher;
                    target.Signature = trust.SignatureSummary;
                }
                else
                {
                    target.Signature = "Файл отсутствует на диске";
                }

                Report.Findings.Add(target);
            }
            else
            {
                // Enrich existing finding if we gained better path/hash/tool info
                if (string.IsNullOrWhiteSpace(target.Sha256) && !string.IsNullOrWhiteSpace(sha256))
                    target.Sha256 = sha256;

                if (string.IsNullOrWhiteSpace(target.DetectedTool) && !string.IsNullOrWhiteSpace(detectedTool))
                    target.DetectedTool = detectedTool;

                if (!File.Exists(target.Path) && !string.IsNullOrWhiteSpace(normPath) && File.Exists(normPath))
                {
                    target.Path = normPath;
                    var trust = TrustEvaluator.Verify(normPath);
                    target.IsSigned = trust.IsValidSignature;
                    target.IsTrustedPublisher = trust.IsTrustedPublisher;
                    target.Publisher = trust.Publisher;
                    target.Signature = trust.SignatureSummary;
                }
            }

            if (!string.IsNullOrWhiteSpace(target.Sha256))
                byHash.TryAdd(target.Sha256, target);
            if (!string.IsNullOrWhiteSpace(normPath))
                byPath.TryAdd(normPath, target);
            if (!string.IsNullOrWhiteSpace(exeKey))
                byExeName.TryAdd(exeKey, target);

            // Avoid adding exact duplicate evidence
            bool dupEvidence = target.Evidences.Any(e =>
                e.SourceType.Equals(evidence.SourceType, StringComparison.OrdinalIgnoreCase) &&
                e.PathOrKey.Equals(evidence.PathOrKey, StringComparison.OrdinalIgnoreCase));

            if (!dupEvidence)
                target.Evidences.Add(evidence);

            RiskEngine.Evaluate(target);
        }
    }

    static string ExtractExeKey(string path, string name)
    {
        string candidate = !string.IsNullOrWhiteSpace(path) ? Path.GetFileName(path) : name;
        if (candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            candidate.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            return candidate;
        return "";
    }

    public void Checked()
    {
        int n = Interlocked.Increment(ref checkedCount);
        Report.ObjectsChecked = n;
    }
}

public interface IScanner
{
    string Name { get; }
    Task ScanAsync(ScanContext context, CancellationToken ct);
}

public static class FileAnalysis
{
    public static async Task<string> ComputeHashAsync(string path, CancellationToken ct)
    {
        using var s = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 65536, useAsync: true);
        return Convert.ToHexString(await SHA256.HashDataAsync(s, ct));
    }

    public static void ReportKnownHash(ScanContext c, string path, ThreatEntry entry, string hash, string sourceType = "SHA-256 база")
    {
        bool confirmed = entry.Confirmed && entry.Sources.Distinct(StringComparer.OrdinalIgnoreCase).Count() >= 2;
        string evType = confirmed ? "SHA-256 база (подтверждено)" : sourceType;
        int score = confirmed ? 90 : 65;

        DateTimeOffset? observed = null;
        try { if (File.Exists(path)) observed = File.GetLastWriteTimeUtc(path); } catch { }

        c.ReportEvidence(
            name: Path.GetFileName(path),
            path: path,
            category: entry.Category,
            evidence: new EvidenceItem
            {
                SourceType = evType,
                Description = confirmed
                    ? $"Точное совпадение SHA-256 с базой угроз ({entry.Name}, источники: {string.Join(", ", entry.Sources)})."
                    : $"Совпадение SHA-256 с индикатором ({entry.Name}).",
                PathOrKey = path,
                ScoreContribution = score,
                ObservedAt = observed
            },
            sha256: hash,
            detectedTool: entry.Name);
    }
}
