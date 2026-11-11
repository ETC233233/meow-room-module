using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace MeowRoom.Services;

/// <summary>从最近的游戏日志里读出人话信息：谁在玩、什么版本、哪个世界、开放的是哪个端口。</summary>
public sealed record GameSession(int Port, string Player, string Version, string World);

public static class GameInfo
{
    private static readonly Regex VersionRx = new(
        @"Loading Minecraft (?<v>[\d.]+)(?: with (?<loader>Fabric|Forge|NeoForge) Loader (?<lv>[\d.]+))?",
        RegexOptions.Compiled);

    private static readonly Regex UserRx = new(@"Setting user: (?<u>\S+)", RegexOptions.Compiled);
    private static readonly Regex PortRx = new(@"Published LAN server on port (?<p>\d+)", RegexOptions.Compiled);

    /// <summary>扫描常见 .minecraft 目录，返回最近 6 小时内启动过的实例。</summary>
    public static List<GameSession> Discover()
    {
        var result = new List<GameSession>();
        foreach (var root in Roots())
        {
            var versions = Path.Combine(root, "versions");
            if (!Directory.Exists(versions)) continue;

            foreach (var dir in Directory.EnumerateDirectories(versions))
            {
                var log = Path.Combine(dir, "logs", "latest.log");
                if (!File.Exists(log)) continue;
                if (DateTime.Now - File.GetLastWriteTime(log) > TimeSpan.FromHours(6)) continue;

                var (player, version, port) = ParseLog(log);
                if (port <= 0) continue;

                result.Add(new GameSession(port, player, version,
                    FindWorld(dir, root, File.GetCreationTime(log))));
            }
        }
        return result;
    }

    private static (string Player, string Version, int Port) ParseLog(string path)
    {
        string player = "", version = "";
        var port = 0;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var sr = new StreamReader(fs, Encoding.UTF8);
            while (sr.ReadLine() is { } line)
            {
                var m = VersionRx.Match(line);
                if (m.Success)
                {
                    version = m.Groups["v"].Value;
                    if (m.Groups["loader"].Success)
                        version += " " + m.Groups["loader"].Value + " " + m.Groups["lv"].Value;
                }

                m = UserRx.Match(line);
                if (m.Success) player = m.Groups["u"].Value;

                m = PortRx.Match(line);
                if (m.Success && int.TryParse(m.Groups["p"].Value, out var p)) port = p;
            }
        }
        catch { }
        return (player, version, port);
    }

    /// <summary>世界名没有直接写在日志里。优先找当前实例目录下的 saves（PCL 默认按版本隔离），再退回全局 saves。</summary>
    private static string FindWorld(string versionDir, string root, DateTime sessionStart)
    {
        foreach (var saves in new[] { Path.Combine(versionDir, "saves"), Path.Combine(root, "saves") })
            if (TryPickWorld(saves, sessionStart) is { Length: > 0 } name) return name;
        return "";
    }

    private static string TryPickWorld(string saves, DateTime sessionStart)
    {
        try
        {
            if (!Directory.Exists(saves)) return "";

            var best = Directory.EnumerateDirectories(saves)
                .Select(d =>
                {
                    var lockFile = Path.Combine(d, "session.lock");
                    var level = Path.Combine(d, "level.dat");
                    var time = File.Exists(lockFile) ? File.GetLastWriteTime(lockFile) : Directory.GetLastWriteTime(d);
                    if (File.Exists(level))
                    {
                        var levelTime = File.GetLastWriteTime(level);
                        if (levelTime > time) time = levelTime;
                    }
                    return new { Dir = d, Time = time };
                })
                .OrderByDescending(x => x.Time)
                .FirstOrDefault();

            if (best is null) return "";
            // 这次游戏启动之后打开过的世界才算；之前玩过的不算
            if (best.Time < sessionStart.AddMinutes(-10)) return "";
            return Path.GetFileName(best.Dir);
        }
        catch { return ""; }
    }

    private static IEnumerable<string> Roots()
    {
        var custom = Environment.GetEnvironmentVariable("MEOW_MC_DIR");
        if (!string.IsNullOrWhiteSpace(custom)) yield return custom;

        var many = Environment.GetEnvironmentVariable("MEOW_MC_DIRS");
        if (!string.IsNullOrWhiteSpace(many))
            foreach (var dir in many.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                yield return dir;

        yield return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), ".minecraft");
    }
}
