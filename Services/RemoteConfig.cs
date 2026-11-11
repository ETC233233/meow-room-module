using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace MeowRoom.Services;

/// <summary>
/// 云下发配置：房间服务地址、中继、边缘 IP 都不写在代码里，启动时从配置入口在线获取。
///
/// 规则：
/// 1. 入口地址和验签公钥都不在源码里，构建时注入（-p:MeowConfigEntry=... -p:MeowConfigKeys=kid:公钥base64,...）。
/// 2. 响应是信封 {payload, sig, kid}：先用 kid 对应公钥验 Ed25519 签名（对 payload 字符串的 UTF-8 字节），再解析 JSON。
/// 3. payload 带 version / issuedAt / expiresAt（unix 秒，时钟容忍 ±5 分钟）；验签失败、过期、版本未知一律视为不可用。
/// 4. 只放内存，不落盘、不进日志；拉不到就报"联机服务暂时不可用"，不退回旧地址。
/// </summary>
public sealed class RemoteConfigData
{
    public string RoomBase { get; init; } = "";
    public string Relay { get; init; } = "";
    public string[] EdgeIps { get; init; } = Array.Empty<string>();
    public bool CfRoute { get; init; }
    public long ExpiresAt { get; init; }
}

public static class RemoteConfig
{
    private const int SupportedVersion = 1;
    private const long SkewSeconds = 300;
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(5) };
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static readonly Regex RelayShape = new(@"^tcp://[A-Za-z0-9.\-]+:\d{2,5}$", RegexOptions.Compiled);

    /// <summary>当前有效配置；没有就是 null。只在内存里。</summary>
    public static RemoteConfigData? Current { get; private set; }

    /// <summary>上一次失败的原因（给界面看，不含地址）。</summary>
    public static string LastError { get; private set; } = "";

    private static string Meta(string key) =>
        typeof(RemoteConfig).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(a => a.Key == key)?.Value ?? "";

    /// <summary>有有效配置就直接返回 true；没有或快过期就重新拉一次。</summary>
    public static async Task<bool> EnsureAsync(CancellationToken ct = default)
    {
        var cur = Current;
        if (cur is not null && cur.ExpiresAt - DateTimeOffset.UtcNow.ToUnixTimeSeconds() > 60) return true;
        await Gate.WaitAsync(ct);
        try
        {
            cur = Current;
            if (cur is not null && cur.ExpiresAt - DateTimeOffset.UtcNow.ToUnixTimeSeconds() > 60) return true;
            return await FetchAsync(ct);
        }
        finally { Gate.Release(); }
    }

    private static async Task<bool> FetchAsync(CancellationToken ct)
    {
        try
        {
            string envelope;
#if DEBUG
            // 仅调试版：从本地文件读未签名配置，方便本地联调；发布版没有这条路。
            var dev = Environment.GetEnvironmentVariable("MEOW_DEV_CONFIG");
            if (!string.IsNullOrWhiteSpace(dev) && File.Exists(dev))
            {
                var data = Parse(File.ReadAllText(dev), allowHttp: true);
                if (data is null) return Fail("本地调试配置无效");
                Current = data;
                LastError = "";
                return true;
            }
#endif
            var entry = Meta("ConfigEntry");
            if (!Uri.TryCreate(entry, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
                return Fail("这个构建没有配置入口");
            envelope = await Http.GetStringAsync(uri, ct);

            var parsed = VerifyEnvelope(envelope);
            if (parsed is null) return Fail("配置验签失败、无效或已过期");
            Current = parsed;
            LastError = "";
            return true;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception)
        {
            return Fail("联机服务暂时不可用");
        }
    }

    /// <summary>先验签再解析；任何一步不对都返回 null。</summary>
    internal static RemoteConfigData? VerifyEnvelope(string envelope)
    {
        try
        {
            using var doc = JsonDocument.Parse(envelope);
            var root = doc.RootElement;
            var payload = root.GetProperty("payload").GetString() ?? "";
            var sig = Convert.FromBase64String(root.GetProperty("sig").GetString() ?? "");
            var kid = root.GetProperty("kid").GetString() ?? "";
            var pk = FindKey(kid);
            if (pk is null || sig.Length != 64) return null;
            var msg = Encoding.UTF8.GetBytes(payload);
            if (!Ed25519.Verify(sig, 0, pk, 0, msg, 0, msg.Length)) return null;
            return Parse(payload, allowHttp: false); // 验签通过才解析 payload
        }
        catch { return null; }
    }

    private static bool Fail(string why)
    {
        Current = null; // 不退回旧地址
        LastError = why;
        return false;
    }

    private static byte[]? FindKey(string kid)
    {
        foreach (var part in Meta("ConfigKeys").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var i = part.IndexOf(':');
            if (i <= 0) continue;
            if (part[..i] != kid) continue;
            try
            {
                var key = Convert.FromBase64String(part[(i + 1)..]);
                return key.Length == 32 ? key : null;
            }
            catch { return null; }
        }
        return null;
    }

    private static RemoteConfigData? Parse(string json, bool allowHttp)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            if (r.GetProperty("version").GetInt32() != SupportedVersion) return null;
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var issued = r.GetProperty("issuedAt").GetInt64();
            var expires = r.GetProperty("expiresAt").GetInt64();
            if (issued > now + SkewSeconds || expires < now - SkewSeconds) return null;

            var roomBase = (r.GetProperty("roomBase").GetString() ?? "").TrimEnd('/');
            if (!Uri.TryCreate(roomBase, UriKind.Absolute, out var u)) return null;
            if (u.Scheme != Uri.UriSchemeHttps && !(allowHttp && u.Scheme == Uri.UriSchemeHttp)) return null;

            var relay = (r.GetProperty("relay").GetString() ?? "").Trim();
            if (!RelayShape.IsMatch(relay)) return null;

            var edges = new List<string>();
            if (r.TryGetProperty("edgeIps", out var arr) && arr.ValueKind == JsonValueKind.Array)
                foreach (var e in arr.EnumerateArray())
                    if (System.Net.IPAddress.TryParse(e.GetString(), out var ip)
                        && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        edges.Add(ip.ToString());

            var cf = r.TryGetProperty("cfRoute", out var c) && c.ValueKind == JsonValueKind.True;
            return new RemoteConfigData
            {
                RoomBase = roomBase, Relay = relay, EdgeIps = edges.ToArray(), CfRoute = cf, ExpiresAt = expires,
            };
        }
        catch { return null; }
    }
}
