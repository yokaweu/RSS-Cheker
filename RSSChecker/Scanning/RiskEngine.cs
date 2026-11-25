using RSSChecker.Models;

namespace RSSChecker.Scanning;

public static class CheatCatalog
{
    public sealed record KnownCheatSignature(string ToolName, string[] Tokens, string Category, int BaseScore);

    public static readonly KnownCheatSignature[] Signatures =
    [
        new("ExLoader", ["exloader"], "CS2 / Cheat Loader", 48),
        new("Neverlose", ["neverlose"], "CS2 Cheat", 52),
        new("Nixware", ["nixware"], "CS2 Cheat", 52),
        new("Midnight", ["midnight.im", "midnight_cs2", "midnight-cs2"], "CS2 Cheat", 50),
        new("Osiris", ["osiris.dll", "osiris_cs2", "osiris-master"], "CS2 Cheat", 48),
        new("Onetap", ["onetap.su", "onetap.com", "onetap_v"], "CS2 Cheat", 50),
        new("Fatality", ["fatality.win", "fatality_cs2"], "CS2 Cheat", 50),
        new("Gamesense / Skeet", ["gamesense.pub", "skeet.cc"], "CS2 Cheat", 52),
        new("Aimware", ["aimware.net", "aimware"], "CS2 Cheat", 50),
        new("Xeno", ["xeno.exe", "xeno_injector", "xeno injector"], "Roblox / DLL Injector", 48),
        new("Solara", ["solara.exe", "solara_bootstrapper", "getsolara"], "Roblox / Executor", 48),
        new("Synapse Z", ["synapsez", "synapse z", "synapse_z"], "Roblox / Executor", 50),
        new("SirHurt", ["sirhurt"], "Roblox / Executor", 48),
        new("Wave Executor", ["wave_executor", "getwave"], "Roblox / Executor", 45)
    ];

    public static readonly string[] CheatContentTokens =
    [
        "aimbot", "wallhack", "triggerbot", "spinbot", "ragebot",
        "legitbot", "glowesp", "entitylist", "dwlocalplayer",
        "cs2 external", "counter-strike cheat", "cheat loader"
    ];

    public static readonly string[] GenericWeakTokens =
    [
        "injector", "loader", "helper", "cheat", "hack"
    ];

    public static bool TryMatchSpecificTool(string text, out KnownCheatSignature? match)
    {
        foreach (var sig in Signatures)
        {
            if (sig.Tokens.Any(t => text.Contains(t, StringComparison.OrdinalIgnoreCase)))
            {
                match = sig;
                return true;
            }
        }
        match = null;
        return false;
    }

    public static bool IsWeakGenericMatch(string text, out string token)
    {
        foreach (var t in GenericWeakTokens)
        {
            if (text.Contains(t, StringComparison.OrdinalIgnoreCase))
            {
                token = t;
                return true;
            }
        }
        token = "";
        return false;
    }
}

public static class RiskEngine
{
    public static void Evaluate(Finding f)
    {
        // Group evidences by SourceType so multiple copies of the same evidence type
        // are NOT counted as independent proofs.
        int score = 0;
        var independentTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var ev in f.Evidences)
        {
            if (independentTypes.Add(ev.SourceType))
            {
                score += ev.ScoreContribution;
            }
            else
            {
                // Same source type repeated: at most a tiny tie-breaker, never stacks
                score += Math.Min(2, ev.ScoreContribution / 10);
            }
        }

        // Signature / Publisher evaluation
        if (f.IsSigned && f.IsTrustedPublisher)
        {
            // Verified trusted publisher (Microsoft, Valve, EasyAntiCheat, etc.)
            bool hasConfirmedHash = f.Evidences.Any(e => e.SourceType == "SHA-256 база (подтверждено)");
            if (!hasConfirmedHash)
            {
                score = 0;
                f.RiskScore = 0;
                f.Status = DetectionStatus.Clean;
                f.Risk = RiskLevel.Clean;
                f.Source = string.Join(" · ", independentTypes);
                f.Reason = $"Проверенный компонент с действительной цифровой подписью ({f.Publisher}).";
                f.LastDetectedAt = f.Evidences.Where(e => e.ObservedAt.HasValue).Select(e => e.ObservedAt).Max();
                return;
            }
        }
        else if (f.IsSigned)
        {
            // Validly signed by another CA: lowers false positive risk
            score = Math.Max(0, score - 25);
        }

        // Clamp 0..100
        score = Math.Clamp(score, 0, 100);
        f.RiskScore = score;

        // Determine status strictly from corroborated evidence & score
        bool hasConfirmedDb = f.Evidences.Any(e => e.SourceType == "SHA-256 база (подтверждено)");
        bool hasSpecificTool = !string.IsNullOrEmpty(f.DetectedTool);
        int strongEvidenceCount = f.Evidences
            .Where(e => e.ScoreContribution >= 20)
            .Select(e => e.SourceType)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        if (hasConfirmedDb || (score >= 80 && (hasSpecificTool || strongEvidenceCount >= 2)))
        {
            f.Status = DetectionStatus.CheatDetected;
            f.Risk = RiskLevel.Critical;
        }
        else if (score >= 55 && independentTypes.Count >= 2)
        {
            f.Status = DetectionStatus.HighRisk;
            f.Risk = RiskLevel.High;
        }
        else if (score >= 30 && (independentTypes.Count >= 2 || hasSpecificTool || strongEvidenceCount >= 1))
        {
            f.Status = DetectionStatus.Suspicious;
            f.Risk = RiskLevel.Medium;
        }
        else if (score >= 5 || !f.IsSigned)
        {
            f.Status = DetectionStatus.Unverified;
            f.Risk = RiskLevel.Low;
        }
        else
        {
            f.Status = DetectionStatus.Clean;
            f.Risk = RiskLevel.Clean;
        }

        f.Source = string.Join(" · ", independentTypes);
        f.LastDetectedAt = f.Evidences.Where(e => e.ObservedAt.HasValue).Select(e => e.ObservedAt).Max();

        // Build clear reason from evidences
        var reasons = f.Evidences
            .GroupBy(e => e.SourceType, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First().Description)
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Distinct()
            .ToList();

        if (!string.IsNullOrEmpty(f.DetectedTool))
            reasons.Insert(0, $"Совпадение с известным инструментом: {f.DetectedTool}.");

        f.Reason = reasons.Count > 0
            ? string.Join(" ", reasons)
            : "Недостаточно данных для точной классификации.";
    }
}
