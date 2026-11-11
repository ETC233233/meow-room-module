using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace MeowRoom.Services;

/// <summary>
/// 从 Minecraft 日志里抓「对局域网开放」的端口。
/// 支持的格式：
///   [Server thread/INFO]: Local game hosted on port 51423      （1.13+）
///   [Server thread/INFO]: Started serving on port 51234       （1.12）
///   [Server thread/INFO]: Started on port 51234
/// </summary>
public sealed class LanHost
{
    private static readonly Regex[] Patterns =
    {
        new(@"Local game hosted on port (\d{2,5})", RegexOptions.Compiled),
        new(@"Published LAN server on port (\d{2,5})", RegexOptions.Compiled),
        new(@"端口号为\[(\d{2,5})\]", RegexOptions.Compiled),
        new(@"Started serving on port (\d{2,5})", RegexOptions.Compiled),
        new(@"Started on port (\d{2,5})", RegexOptions.Compiled),
    };

    private LanHost() { }

    /// <summary>挑最新的运行日志：根目录那份，或 versions/&lt;名称&gt;/logs 下的（PCL 开版本隔离时只更新后者）。</summary>
    public static string LogPath(string mcDir)
    {
        var best = Path.Combine(mcDir, "logs", "latest.log");
        try
        {
            var newest = File.Exists(best) ? File.GetLastWriteTimeUtc(best) : DateTime.MinValue;
            var verDir = Path.Combine(mcDir, "versions");
            if (Directory.Exists(verDir))
            {
                foreach (var f in Directory.EnumerateFiles(verDir, "latest.log", SearchOption.AllDirectories))
                {
                    var t = File.GetLastWriteTimeUtc(f);
                    if (t > newest) { newest = t; best = f; }
                }
            }
        }
        catch { }
        return best;
    }

    /// <summary>在已有日志里找最近一次开放的端口（不等待）。</summary>
    public static int? Peek(string mcDir)
    {
        var path = LogPath(mcDir);
        if (!File.Exists(path)) return null;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var len = (int)Math.Min(fs.Length, 2 * 1024 * 1024); // 只看最后 2MB
            fs.Seek(-len, SeekOrigin.End);
            var buf = new byte[len];
            var read = fs.Read(buf, 0, len);
            return Scan(Encoding.UTF8.GetString(buf, 0, read));
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    /// <summary>等日志里出现新的开放端口；超时返回 null。</summary>
    public static async Task<int?> WaitAsync(string mcDir, TimeSpan timeout, CancellationToken ct = default)
    {
        var path = LogPath(mcDir);
        var deadline = DateTime.UtcNow + timeout;
        long offset = 0;
        var startOffsetKnown = false;

        var buffer = new StringBuilder();

        while (DateTime.UtcNow < deadline && !ct.IsCancellationRequested)
        {
            try
            {
                if (File.Exists(path))
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    if (!startOffsetKnown)
                    {
                        // 先扫一遍已有内容（可能刚开放就启动监听）
                        var all = (int)Math.Min(fs.Length, 2 * 1024 * 1024);
                        fs.Seek(-all, SeekOrigin.End);
                        var buf = new byte[all];
                        var r = fs.Read(buf, 0, all);
                        var text0 = Encoding.UTF8.GetString(buf, 0, r);
                        var hit = Scan(text0);
                        if (hit.HasValue) return hit;
                        // 保留最后一行残片，避免「端口行被拆在两次写入之间」漏掉
                        var nl = text0.LastIndexOf((char)10);
                        buffer.Clear();
                        buffer.Append(nl >= 0 ? text0[(nl + 1)..] : text0);
                        offset = fs.Length;
                        startOffsetKnown = true;
                    }
                    else if (fs.Length < offset)
                    {
                        // 日志轮转，从头再来
                        offset = 0;
                    }

                    if (fs.Length > offset)
                    {
                        fs.Seek(offset, SeekOrigin.Begin);
                        var buf = new byte[fs.Length - offset];
                        var r = fs.Read(buf, 0, buf.Length);
                        offset += r;
                        buffer.Append(Encoding.UTF8.GetString(buf, 0, r));

                        var text = buffer.ToString();
                        var lastNl = text.LastIndexOf('\n');
                        if (lastNl >= 0)
                        {
                            var complete = text.Substring(0, lastNl);
                            buffer.Clear();
                            buffer.Append(text.Substring(lastNl + 1));
                            var hit = Scan(complete);
                            if (hit.HasValue) return hit;
                        }
                    }
                }
            }
            catch (IOException) { /* 日志正被写，下一轮再试 */ }
            catch (UnauthorizedAccessException) { return null; }

            await Task.Delay(250, ct).ConfigureAwait(false);
        }

        return null;
    }

    private static int? Scan(string text)
    {
        int? found = null;
        foreach (var line in text.Split('\n'))
        {
            foreach (var re in Patterns)
            {
                var m = re.Match(line);
                if (m.Success && int.TryParse(m.Groups[1].Value, out var port) && port is > 0 and < 65536)
                {
                    found = port; // 取最后一次
                }
            }
        }
        return found;
    }
}
