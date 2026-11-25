# RSS | checker

Windows 10/11 desktop diagnostic app built with C#/.NET 10 WPF. It is read-only and keeps scan data local.

## Build and run

Open `RSSChecker.sln` in Visual Studio with the .NET 10 Windows Desktop workload, or run `dotnet build RSSChecker.sln -c Release` on Windows. The framework-dependent output is `RSSChecker/bin/Release/net10.0-windows/RSSChecker.exe`.

## Detection and coverage

- Process scanner enumerates readable processes and hashes their executable images. It notes CS2 process presence but does not inspect process memory, loaded modules, injection events, or remote threads.
- File scanner hashes EXE/DLL/SYS files in common user folders and Windows Temp. Full Scan also traverses selected Users, ProgramData, and Games directories on fixed drives. Exclusions and sensitivity settings apply to this scanner.
- Persistence scanner reads common Run/RunOnce keys, scheduled-task files, and service image paths. Protected entries may be skipped.
- Game scanner locates standard Steam folders and compares discovered files against imported SHA-256 values. It does not verify Steam depot manifests; ordinary game-file integrity is not proven.
- Artifact scan checks a weak Prefetch filename heuristic and records its coverage limitations. It does not inspect Security logs, Amcache, memory, or kernel state.
- An embedded certificate is displayed as metadata only; Windows trust and revocation are not verified. A filename, unsigned file, or injector catalog entry alone is never a detection.

## Categories and confidence

The Known Injectors catalog contains the eleven user-requested names once each, under `Known Injectors · Roblox related`. All are Unverified reference names and are not matched by filename or attributed to CS2. No public hash indicators for these names or CS2 cheats are bundled.

A hash hit is Confirmed only when the imported record marks it confirmed and has at least two distinct source URLs. Other exact hash matches remain Unverified. Heuristics with multiple signals are Suspicious. No hit is shown as a scoped clean result with coverage notes.

## Indicator feeds

The app supports manual import of local JSON and public HTTPS JSON feed URLs. Each entry includes source URL references. Automatic updates are opt-in, run only while the app is open, and use the selected interval. The app downloads indicator metadata only; it never downloads or executes samples and never uploads local files or hashes.

Example feed:

```json
{
  "version": 1,
  "updatedAt": "2026-11-25T00:00:00Z",
  "source": "Public research feed",
  "entries": [
    {
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "name": "Example indicator",
      "category": "CS2 Cheats",
      "sources": ["https://research.example/report-a", "https://research.example/report-b"],
      "sourceUrl": "https://research.example/report-a",
      "confirmed": true
    }
  ]
}
```

Feed source: ThreatFox's public API/export requires an abuse.ch Auth-Key; no key is embedded in the app. Configure a source you trust in Settings. Feed contents and source references are not independently validated by RSS Checker, so use trusted publishers. One source remains Unverified.

## Local data

Settings, scan history, and imported indicators are stored under `%LOCALAPPDATA%\\RSSChecker`. JSON and HTML reports are saved to the configured local report directory. Scans do not modify system files, processes, services, or security settings.
