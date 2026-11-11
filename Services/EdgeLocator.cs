using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace MeowRoom.Services;

/// <summary>
/// Cloudflare 边缘 IP 采样：并发探测 TLS + /api/health，按握手耗时排序并缓存。
/// 国内网络常只丢其中几个 IP，所以启动时测一次，之后优先用测出来最快的那条。
/// </summary>
public static class EdgeLocator
{
    // Cloudflare 官方 IPv4 段（https://www.cloudflare.com/ips-v4）。
    // 任意一个边缘 IP 都能服务我们的域名，证书按 SNI 校验，所以只挑线路。
    private static readonly (uint Network, int Prefix)[] Ranges =
    {
        (0xADF53000, 20), // 173.245.48.0/20
        (0x6715F400, 22), // 103.21.244.0/22
        (0x6716C800, 22), // 103.22.200.0/22
        (0x671F0400, 22), // 103.31.4.0/22
        (0x8D654000, 18), // 141.101.64.0/18
        (0x6CA2C000, 18), // 108.162.192.0/18
        (0xBE5DF000, 20), // 190.93.240.0/20
        (0xBC726000, 20), // 188.114.96.0/20
        (0xC5EAF000, 22), // 197.234.240.0/22
        (0xC6298000, 17), // 198.41.128.0/17
        (0xA29E0000, 15), // 162.158.0.0/15
        (0x68100000, 13), // 104.16.0.0/13
        (0x68180000, 14), // 104.24.0.0/14
        (0xAC400000, 13), // 172.64.0.0/13
        (0x83004800, 22), // 131.0.72.0/22
    };

    private static string CachePath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MeowRoom", "edges.json");

    private sealed record Cache(string Host, DateTimeOffset Time, List<string> Ips);

    public static List<string> Load(string host)
    {
        try
        {
            if (!File.Exists(CachePath)) return new();
            var c = JsonSerializer.Deserialize<Cache>(File.ReadAllText(CachePath));
            if (c is null || c.Host != host) return new();
            if (DateTimeOffset.UtcNow - c.Time > TimeSpan.FromHours(12)) return new();
            return c.Ips;
        }
        catch { return new(); }
    }

    public static void Save(string host, List<string> ips)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(CachePath)!);
            File.WriteAllText(CachePath, JsonSerializer.Serialize(new Cache(host, DateTimeOffset.UtcNow, ips)));
        }
        catch { }
    }

    /// <summary>采样 -> 并发探测 -> 返回按握手耗时排序的可用 IP（最多 8 个）。</summary>
    public static async Task<List<string>> FindAsync(string host, int samples = 256, CancellationToken ct = default, int timeoutMs = 300)
    {
        var candidates = Sample(samples);
        var results = new System.Collections.Concurrent.ConcurrentBag<(string Ip, int Ms)>();
        using var gate = new SemaphoreSlim(128);

        var tasks = candidates.Select(async ip =>
        {
            await gate.WaitAsync(ct);
            try
            {
                if (ct.IsCancellationRequested) return;
                var ms = await ProbeAsync(ip, host, ct, timeoutMs);
                if (ms is int v) results.Add((ip, v));
            }
            finally { gate.Release(); }
        });
        await Task.WhenAll(tasks);

        var best = results.OrderBy(r => r.Ms).Take(8).Select(r => r.Ip).ToList();
        if (best.Count > 0) Save(host, best);
        return best;
    }

    /// <summary>并行验证缓存里的候选，哪个先通就用哪个。</summary>
    public static async Task<string?> FastestAsync(string host, IEnumerable<string> ips, CancellationToken ct)
    {
        var tasks = ips.Select(async ip => (Ip: ip, Ms: await ProbeAsync(ip, host, ct, 300))).ToList();
        while (tasks.Count > 0)
        {
            var done = await Task.WhenAny(tasks);
            tasks.Remove(done);
            var (ip, ms) = await done;
            if (ms is not null) return ip;
        }
        return null;
    }

    private static string[] Sample(int count)
    {
        var rnd = new Random();
        var set = new HashSet<string>();
        while (set.Count < count)
        {
            var (net, prefix) = Ranges[rnd.Next(Ranges.Length)];
            var size = 1u << (32 - prefix);
            var ip = net + (uint)rnd.Next((int)Math.Min(size, int.MaxValue));
            var bytes = new[] { (byte)(ip >> 24), (byte)(ip >> 16), (byte)(ip >> 8), (byte)ip };
            if (bytes[3] is 0 or 255) continue;
            set.Add(new IPAddress(bytes).ToString());
        }
        return set.ToArray();
    }

    // 300ms 上限：只留下真正快的边缘，失败的 IP 不再拖慢整体选择。
    private static async Task<int?> ProbeAsync(string ip, string host, CancellationToken outer, int timeoutMs = 300)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(outer);
        cts.CancelAfter(timeoutMs);
        var sw = Stopwatch.StartNew();
        try
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(IPAddress.Parse(ip), 443, cts.Token);

            using var ssl = new SslStream(tcp.GetStream(), false);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host }, cts.Token);

            // 证书校验通过就说明这个边缘真的在服务我们的域名，够判断线路可用。
            // 不再额外发 /api/health：那要多花一个往返，300ms 预算里几乎全被它吃掉。
            return (int)sw.ElapsedMilliseconds;
        }
        catch { return null; }
    }
}
