using System.Net.Http;
using System.Text.Json;
using RSSChecker.Models;
namespace RSSChecker.Services;
public sealed class AppDataService
{
 readonly string dir=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"RSSChecker"); public string DatabasePath=>Path.Combine(dir,"threat-db.json"); public string SettingsPath=>Path.Combine(dir,"settings.json"); public string HistoryPath=>Path.Combine(dir,"history.json");
 static readonly JsonSerializerOptions json=new(){WriteIndented=true,PropertyNameCaseInsensitive=true};
 public async Task<ThreatDatabase> LoadDatabaseAsync(){Directory.CreateDirectory(dir);if(!File.Exists(DatabasePath)){var d=new ThreatDatabase();await SaveDatabaseAsync(d);return d;}try{return JsonSerializer.Deserialize<ThreatDatabase>(await File.ReadAllTextAsync(DatabasePath),json)??new();}catch{return new();}}
 public Task SaveDatabaseAsync(ThreatDatabase db)=>File.WriteAllTextAsync(DatabasePath,JsonSerializer.Serialize(db,json));
 public async Task<AppSettings> LoadSettingsAsync(){Directory.CreateDirectory(dir);try{return File.Exists(SettingsPath)?JsonSerializer.Deserialize<AppSettings>(await File.ReadAllTextAsync(SettingsPath),json)??new():new();}catch{return new();}}
 public Task SaveSettingsAsync(AppSettings s)=>File.WriteAllTextAsync(SettingsPath,JsonSerializer.Serialize(s,json));
 public async Task<List<ScanReport>> LoadHistoryAsync(){try{return File.Exists(HistoryPath)?JsonSerializer.Deserialize<List<ScanReport>>(await File.ReadAllTextAsync(HistoryPath),json)??[]:[];}catch{return[];}}
 public async Task SaveHistoryAsync(ScanReport report){var h=await LoadHistoryAsync();h.Insert(0,report);await File.WriteAllTextAsync(HistoryPath,JsonSerializer.Serialize(h.Take(50),json));}
}
public sealed class IndicatorFeedService
{
 static readonly HttpClient client=new(new HttpClientHandler{AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(25)};
 public async Task<ThreatDatabase> FetchAsync(string url,CancellationToken ct)
 {
  if(!Uri.TryCreate(url,UriKind.Absolute,out var uri)||uri.Scheme!=Uri.UriSchemeHttps)throw new InvalidDataException("Enter a public HTTPS JSON feed address.");
  using var req=new HttpRequestMessage(HttpMethod.Get,uri);req.Headers.UserAgent.ParseAdd("RSSChecker/1.0");using var resp=await client.SendAsync(req,HttpCompletionOption.ResponseHeadersRead,ct);resp.EnsureSuccessStatusCode();if(resp.Content.Headers.ContentLength>20_000_000)throw new InvalidDataException("Feed exceeds the 20 MB safety limit.");await using var stream=await resp.Content.ReadAsStreamAsync(ct);using var ms=new MemoryStream();var buf=new byte[81920];int n;while((n=await stream.ReadAsync(buf,ct))>0){if(ms.Length+n>20_000_000)throw new InvalidDataException("Feed exceeds the 20 MB safety limit.");await ms.WriteAsync(buf.AsMemory(0,n),ct);}var db=JsonSerializer.Deserialize<ThreatDatabase>(ms.ToArray(),new JsonSerializerOptions{PropertyNameCaseInsensitive=true})??throw new InvalidDataException("Feed is not a valid RSS Checker indicator database.");if(db.Entries.Count>250_000)throw new InvalidDataException("Feed contains too many entries.");foreach(var e in db.Entries){if(e.Sha256.Length!=64||!e.Sha256.All(Uri.IsHexDigit))throw new InvalidDataException("Feed has an invalid SHA-256 value.");if(e.Sources.Count==0||e.Sources.Any(s=>!Uri.TryCreate(s,UriKind.Absolute,out var source)||source.Scheme is not ("http" or "https")))throw new InvalidDataException("Every indicator must provide at least one HTTP(S) source URL.");if(string.IsNullOrWhiteSpace(e.Category))throw new InvalidDataException("Every indicator requires a category.");e.Confirmed=e.Confirmed&&e.Sources.Distinct(StringComparer.OrdinalIgnoreCase).Count()>=2;}
  db.Source=uri.GetLeftPart(UriPartial.Authority);db.UpdatedAt=DateTimeOffset.Now;return db;
 }
 public async Task<int> MergeAsync(AppDataService store,string url,CancellationToken ct){var fresh=await FetchAsync(url,ct);var current=await store.LoadDatabaseAsync();var map=current.Entries.ToDictionary(x=>x.Sha256,x=>x,StringComparer.OrdinalIgnoreCase);foreach(var e in fresh.Entries){if(map.TryGetValue(e.Sha256,out var old)){old.Sources=old.Sources.Concat(e.Sources).Distinct(StringComparer.OrdinalIgnoreCase).ToList();old.Confirmed=(old.Confirmed||e.Confirmed)&&old.Sources.Count>=2;if(string.IsNullOrWhiteSpace(old.Name))old.Name=e.Name;if(string.IsNullOrWhiteSpace(old.Category)||old.Category=="General")old.Category=e.Category;}else map[e.Sha256]=e;}current.Entries=map.Values.ToList();current.Source=url;current.UpdatedAt=DateTimeOffset.Now;await store.SaveDatabaseAsync(current);return fresh.Entries.Count;}
}
public static class ReportExport
{
 public static Task JsonAsync(ScanReport r,string p)=>File.WriteAllTextAsync(p,JsonSerializer.Serialize(r,new JsonSerializerOptions{WriteIndented=true}));
 public static Task HtmlAsync(ScanReport r,string p){static string E(string s)=>System.Net.WebUtility.HtmlEncode(s);string rows=string.Join("",r.Findings.Select(f=>$"<tr><td>{E(f.Status.ToString())}</td><td>{E(f.Name)}</td><td>{E(f.Category)}</td><td>{E(f.Path)}</td><td>{E(f.Sha256)}</td><td>{E(f.Source)}</td><td>{E(f.Reason)}</td><td>{E(f.CheckedAt.ToString("O"))}</td></tr>"));string html=$"<!doctype html><meta charset='utf-8'><title>RSS Checker report</title><style>body{{font:14px Segoe UI;background:#101018;color:#eee;padding:28px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #393747;padding:8px;text-align:left;overflow-wrap:anywhere}}th{{background:#242132}}</style><h1>RSS Checker report</h1><p>{E(r.Mode)} · {E(r.StartedAt.ToString("O"))} — {E(r.FinishedAt?.ToString("O")??"in progress")} · {r.ObjectsChecked} checked</p><table><tr><th>Status</th><th>Object</th><th>Category</th><th>Path</th><th>SHA-256</th><th>Source</th><th>Reason</th><th>Checked</th></tr>{rows}</table><h2>Coverage notes</h2><ul>{string.Join("",r.Notes.Select(n=>$"<li>{E(n)}</li>"))}</ul>";return File.WriteAllTextAsync(p,html);}
}
