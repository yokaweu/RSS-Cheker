namespace RSSChecker.Models;

public enum RiskLevel { Clean, Low, Medium, High, Critical }

public enum DetectionStatus
{
    Clean,
    Unverified,
    Suspicious,
    HighRisk,
    CheatDetected
}

public sealed class EvidenceItem
{
    public string SourceType { get; set; } = "";
    public string Description { get; set; } = "";
    public string PathOrKey { get; set; } = "";
    public int ScoreContribution { get; set; }
    public DateTimeOffset? ObservedAt { get; set; }
}

public sealed class Finding
{
    public string Name { get; set; } = "";
    public string Category { get; set; } = "";
    public string Path { get; set; } = "";
    public string NormalizedKey { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public string Signature { get; set; } = "Not checked";
    public string Publisher { get; set; } = "";
    public bool IsSigned { get; set; }
    public bool IsTrustedPublisher { get; set; }
    public string DetectionType { get; set; } = "";
    public RiskLevel Risk { get; set; } = RiskLevel.Low;
    public int RiskScore { get; set; }
    public DetectionStatus Status { get; set; } = DetectionStatus.Unverified;
    public string DetectedTool { get; set; } = "";
    public string Source { get; set; } = "";
    public DateTimeOffset CheckedAt { get; set; } = DateTimeOffset.Now;
    public DateTimeOffset? LastDetectedAt { get; set; }
    public string Reason { get; set; } = "";
    public DateTimeOffset DetectedAt { get; set; } = DateTimeOffset.Now;
    public List<EvidenceItem> Evidences { get; set; } = [];

    public string StatusDisplay => Status switch
    {
        DetectionStatus.CheatDetected => "Cheat Detected",
        DetectionStatus.HighRisk => "High Risk",
        DetectionStatus.Suspicious => "Suspicious",
        DetectionStatus.Unverified => "Unverified",
        DetectionStatus.Clean => "Clean",
        _ => Status.ToString()
    };

    public int StatusSortOrder => Status switch
    {
        DetectionStatus.CheatDetected => 0,
        DetectionStatus.HighRisk => 1,
        DetectionStatus.Suspicious => 2,
        DetectionStatus.Unverified => 3,
        DetectionStatus.Clean => 4,
        _ => 5
    };

    public string LastDetectedDisplay => LastDetectedAt?.ToString("g") ?? "—";
}

public sealed class ScanReport
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTimeOffset StartedAt { get; set; } = DateTimeOffset.Now;
    public DateTimeOffset? FinishedAt { get; set; }
    public string Mode { get; set; } = "";
    public int ObjectsChecked { get; set; }
    public List<Finding> Findings { get; set; } = [];
    public List<string> Notes { get; set; } = [];
}

public sealed class ThreatDatabase
{
    public int Version { get; set; } = 1;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.Now;
    public string Source { get; set; } = "Local import";
    public List<ThreatEntry> Entries { get; set; } = [];
}

public sealed class ThreatEntry
{
    public string Sha256 { get; set; } = "";
    public string Name { get; set; } = "";
    public string Category { get; set; } = "CS2 Cheats";
    public List<string> Sources { get; set; } = [];
    public string SourceUrl { get; set; } = "";
    public bool Confirmed { get; set; }
    public DateTimeOffset? PublishedAt { get; set; }
}

public sealed class AppSettings
{
    public string Theme { get; set; } = "Dark";
    public string AnimationIntensity { get; set; } = "Normal";
    public string ScanSensitivity { get; set; } = "Balanced";
    public List<string> Exclusions { get; set; } = [];
    public bool AutomaticDatabaseUpdates { get; set; }
    public int UpdateIntervalHours { get; set; } = 24;
    public string DatabaseFeedUrl { get; set; } = "";
    public string ReportDirectory { get; set; } = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    public string Language { get; set; } = "Русский";
}

public sealed record InjectorReference(string Name, string Category, string Confidence, string Source);
