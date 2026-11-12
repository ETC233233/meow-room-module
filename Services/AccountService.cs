using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;

namespace MeowRoom.Services;

/// <summary>收到的一条邀请。RoomCode 可能为空（只是「来一起玩」的邀请，还没有房间）。</summary>
public sealed record InviteEvent(string FromUuid, string FromName, string RoomCode, long Timestamp);

/// <summary>对方回复了你发出的邀请。Accepted=false 表示拒绝。</summary>
public sealed record InviteReplyEvent(string FromUuid, string FromName, bool Accepted, long Timestamp);

/// <summary>
/// 玩家身份证明：Mojang 签发的玩家证书（公钥 + Mojang 的签名）加上证书私钥对挑战码的签名。
/// 由宿主在本机生成（令牌只发给 Mojang），模块和服务端都看不到令牌与私钥。
/// </summary>
public sealed record LoginProof(string Uuid, string PublicKey, long ExpiresAtMs, string CertSignature, string Signature);

/// <summary>账号服务返回的会话。Developer 表示这个账号在服务端的开发者名单里。</summary>
public sealed record AccountSession(string Token, string Uuid, string Name, long ExpiresAtMs, bool Developer);

/// <summary>
/// 账号服务客户端：Minecraft 登录握手 → 会话票 → 邀请推送。<b>服务端不接触任何微软 / Mojang 令牌。</b>
///
/// 登录流程：
/// 1. 向账号服务要一个一次性挑战码 serverId；
/// 2. 宿主（<c>prove</c> 委托）在本机向 Mojang 申请玩家证书，并用证书私钥对挑战码签名——令牌只发给 Mojang，
///    私钥不出本机，所以这一步由宿主提供，模块不碰它们；
/// 3. 账号服务用 Mojang 的公开密钥验证证书章（公钥属于这个 UUID）和挑战码签名，签发会话票；它不请求 Mojang。
///
/// 推送通道：WebSocket，每 30 秒心跳、10 秒没回应就重连；会话过期（连接被 401 拒绝）触发 <see cref="SessionExpired"/>。
/// 联机总开关（<see cref="OnlineSwitch"/>）关着时，所有网络调用都直接返回失败。
/// </summary>
public sealed class AccountService : IDisposable
{
    public const int HeartbeatSeconds = 30;
    public const int PongTimeoutSeconds = 10;

    private readonly HttpClient _http;
    private AccountSession? _session;

    public event Action<string>? Log;

    /// <summary>收到邀请（在后台线程触发，宿主自行切回界面线程）。</summary>
    public event Action<InviteEvent>? Invite;

    /// <summary>对方回复了邀请（在后台线程触发）。</summary>
    public event Action<InviteReplyEvent>? InviteReply;

    /// <summary>会话过期或被服务端拒绝：宿主应让用户重新登录。</summary>
    public event Action? SessionExpired;

    public AccountSession? Session => _session;
    public bool IsLoggedIn => _session is { } s && s.ExpiresAtMs > DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    public AccountService(HttpClient? http = null) =>
        _http = http ?? new HttpClient { Timeout = Timeout.InfiniteTimeSpan };

    // ------------------------------------------------------------------ 登录

    /// <param name="playerName">玩家名（只用于显示，UUID 才是权威身份）。</param>
    /// <param name="prove">宿主实现：拿 serverId 生成身份证明；失败返回 null（原因由宿主自己提示）。</param>
    public async Task<(bool Ok, string Message)> LoginAsync(string playerName,
        Func<string, CancellationToken, Task<LoginProof?>> prove, CancellationToken ct = default)
    {
        var baseUrl = await BaseAsync(ct);
        if (baseUrl is null) return (false, RemoteConfig.LastError.Length > 0 ? RemoteConfig.LastError : "联机服务暂时不可用");

        try
        {
            using var chRes = await SendAsync(HttpMethod.Get, baseUrl + "/auth/challenge", null, null, TimeSpan.FromSeconds(15), ct);
            var ch = JsonSerializer.Deserialize<JsonElement>(await chRes.Content.ReadAsStringAsync(ct));
            if (!chRes.IsSuccessStatusCode || !ch.TryGetProperty("serverId", out var sid))
                return (false, "取登录挑战码失败：" + ErrorOf(ch, (int)chRes.StatusCode));
            var serverId = sid.GetString() ?? "";

            var proof = await prove(serverId, ct);
            if (proof is null)
                return (false, "生成登录证明失败（账号令牌可能已过期，请重新登录账号）");

            using var vRes = await SendAsync(HttpMethod.Post, baseUrl + "/auth/verify",
                new
                {
                    serverId,
                    uuid = proof.Uuid,
                    name = playerName,
                    publicKey = proof.PublicKey,
                    expiresAtMs = proof.ExpiresAtMs,
                    certSignature = proof.CertSignature,
                    signature = proof.Signature,
                }, null, TimeSpan.FromSeconds(20), ct);
            var v = JsonSerializer.Deserialize<JsonElement>(await vRes.Content.ReadAsStringAsync(ct));
            if (!vRes.IsSuccessStatusCode || !v.TryGetProperty("token", out var tok))
                return (false, ErrorOf(v, (int)vRes.StatusCode));

            _session = new AccountSession(
                tok.GetString() ?? "",
                v.GetProperty("uuid").GetString() ?? "",
                v.GetProperty("name").GetString() ?? playerName,
                v.GetProperty("exp").GetInt64(),
                v.TryGetProperty("developer", out var dev) && dev.ValueKind == JsonValueKind.True);
            return (true, "已登录联机账号");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            return (false, "联机登录失败：" + ex.Message);
        }
    }

    public void Logout() => _session = null;

    // ------------------------------------------------------------------ 邀请

    /// <summary>向一个玩家发邀请。Delivered=false 表示对方当前不在线（或被限流），不是错误。</summary>
    public async Task<(bool Ok, bool Delivered, string Message)> InviteAsync(string toUuid, string roomCode = "",
        CancellationToken ct = default)
    {
        var baseUrl = await BaseAsync(ct);
        if (baseUrl is null) return (false, false, "联机服务暂时不可用");
        if (!IsLoggedIn) return (false, false, "还没有登录联机账号");
        try
        {
            using var res = await SendAsync(HttpMethod.Post, baseUrl + "/invite",
                new { toUuid, roomCode = string.IsNullOrEmpty(roomCode) ? null : roomCode },
                _session!.Token, TimeSpan.FromSeconds(20), ct);
            var j = JsonSerializer.Deserialize<JsonElement>(await res.Content.ReadAsStringAsync(ct));
            if ((int)res.StatusCode == 401) { _session = null; SessionExpired?.Invoke(); return (false, false, "会话已过期，请重新登录"); }
            if (!res.IsSuccessStatusCode) return (false, false, ErrorOf(j, (int)res.StatusCode));
            var delivered = j.TryGetProperty("delivered", out var d) && d.ValueKind == JsonValueKind.True;
            return (true, delivered, delivered ? "邀请已送达" : "对方现在不在线（或刚邀请过）");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            return (false, false, "发送邀请失败：" + ex.Message);
        }
    }

    /// <summary>回复收到的邀请。服务端只允许回复收到过的邀请，且一次邀请只能回复一次（10 分钟内有效）。</summary>
    public async Task<(bool Ok, bool Delivered, string Message)> ReplyInviteAsync(string toUuid, bool accepted,
        CancellationToken ct = default)
    {
        var baseUrl = await BaseAsync(ct);
        if (baseUrl is null) return (false, false, "联机服务暂时不可用");
        if (!IsLoggedIn) return (false, false, "还没有登录联机账号");
        try
        {
            using var res = await SendAsync(HttpMethod.Post, baseUrl + "/invite/reply",
                new { toUuid, accepted }, _session!.Token, TimeSpan.FromSeconds(20), ct);
            var j = JsonSerializer.Deserialize<JsonElement>(await res.Content.ReadAsStringAsync(ct));
            if ((int)res.StatusCode == 401) { _session = null; SessionExpired?.Invoke(); return (false, false, "会话已过期，请重新登录"); }
            if (!res.IsSuccessStatusCode) return (false, false, ErrorOf(j, (int)res.StatusCode));
            var delivered = j.TryGetProperty("delivered", out var d) && d.ValueKind == JsonValueKind.True;
            return (true, delivered, delivered ? "已回复" : "已回复（对方现在不在线，没收到）");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            return (false, false, "回复邀请失败：" + ex.Message);
        }
    }

    // ------------------------------------------------------------------ 推送通道

    /// <summary>连上推送通道并一直保持，直到被取消、会话过期或联机开关被关掉。</summary>
    public async Task RunPushAsync(CancellationToken ct)
    {
        var wait = 1000;
        while (!ct.IsCancellationRequested)
        {
            if (!OnlineSwitch.Enabled) { Log?.Invoke(OnlineSwitch.DisabledMessage); return; }
            var session = _session;
            if (session is null || !IsLoggedIn) { Log?.Invoke("没有有效的联机会话，推送通道不连接"); return; }

            try
            {
                var baseUrl = await BaseAsync(ct);
                if (baseUrl is null) throw new InvalidOperationException("没有服务配置");
                var wsUrl = baseUrl.Replace("https://", "wss://").Replace("http://", "ws://") + "/ws";

                using var ws = new ClientWebSocket();
                ws.Options.SetRequestHeader("Authorization", "Bearer " + session.Token);
                await ws.ConnectAsync(new Uri(wsUrl), ct);
                wait = 1000;
                Log?.Invoke("邀请推送通道已连接");

                long lastRx = Environment.TickCount64;
                using var hb = CancellationTokenSource.CreateLinkedTokenSource(ct);
                _ = Task.Run(() => HeartbeatAsync(ws, () => Interlocked.Read(ref lastRx), hb.Token), hb.Token);

                try
                {
                    var buf = new byte[16384];
                    while (!ct.IsCancellationRequested && ws.State == WebSocketState.Open)
                    {
                        using var ms = new MemoryStream();
                        WebSocketReceiveResult r;
                        do
                        {
                            r = await ws.ReceiveAsync(new ArraySegment<byte>(buf), ct);
                            if (r.MessageType == WebSocketMessageType.Close) break;
                            ms.Write(buf, 0, r.Count);
                        } while (!r.EndOfMessage);
                        if (r.MessageType == WebSocketMessageType.Close) break;
                        Interlocked.Exchange(ref lastRx, Environment.TickCount64);
                        HandleMessage(Encoding.UTF8.GetString(ms.ToArray()));
                    }
                }
                finally { hb.Cancel(); }
            }
            catch (Exception ex)
            {
                if (ct.IsCancellationRequested) return;
                if (ex is WebSocketException && ex.Message.Contains("401", StringComparison.Ordinal))
                {
                    _session = null;
                    SessionExpired?.Invoke();
                    return;
                }
                Log?.Invoke("邀请推送通道断开：" + ex.Message + "，重连中");
            }

            try { await Task.Delay(wait, ct); } catch { return; }
            wait = Math.Min(wait * 2, 30_000);
        }
    }

    private void HandleMessage(string text)
    {
        try
        {
            using var doc = JsonDocument.Parse(text);
            var root = doc.RootElement;
            var type = root.TryGetProperty("type", out var t) ? t.GetString() : "";
            if (type == "invite_reply")
            {
                var rf = root.GetProperty("from");
                InviteReply?.Invoke(new InviteReplyEvent(
                    rf.GetProperty("uuid").GetString() ?? "",
                    rf.GetProperty("name").GetString() ?? "",
                    root.TryGetProperty("accepted", out var acc) && acc.ValueKind == JsonValueKind.True,
                    root.TryGetProperty("ts", out var rts) && rts.ValueKind == JsonValueKind.Number ? rts.GetInt64() : 0));
                return;
            }
            if (type != "invite") return;          // hello / pong 等不用处理
            var from = root.GetProperty("from");
            Invite?.Invoke(new InviteEvent(
                from.GetProperty("uuid").GetString() ?? "",
                from.GetProperty("name").GetString() ?? "",
                root.TryGetProperty("roomCode", out var rc) ? rc.GetString() ?? "" : "",
                root.TryGetProperty("ts", out var ts) && ts.ValueKind == JsonValueKind.Number ? ts.GetInt64() : 0));
        }
        catch { /* 格式不对的消息直接忽略 */ }
    }

    private async Task HeartbeatAsync(ClientWebSocket ws, Func<long> lastRx, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(HeartbeatSeconds), ct);
                var sentAt = Environment.TickCount64;
                await ws.SendAsync(Encoding.UTF8.GetBytes("ping"), WebSocketMessageType.Text, true, ct);
                await Task.Delay(TimeSpan.FromSeconds(PongTimeoutSeconds), ct);
                if (lastRx() < sentAt)
                {
                    Log?.Invoke("邀请推送通道心跳超时，重连");
                    ws.Abort();
                    return;
                }
            }
        }
        catch { /* 取消或连接已断：由 RunPushAsync 处理 */ }
    }

    // ------------------------------------------------------------------ 内部

    private static async Task<string?> BaseAsync(CancellationToken ct)
    {
        if (!await RemoteConfig.EnsureAsync(ct)) return null;
        var b = RemoteConfig.Current?.AccountBase ?? "";
        return b.Length == 0 ? null : b;
    }

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string url, object? payload, string? token,
        TimeSpan timeout, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(method, url);
        if (!string.IsNullOrEmpty(token)) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (payload is not null)
            req.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        return await _http.SendAsync(req, HttpCompletionOption.ResponseContentRead, cts.Token);
    }

    private static string ErrorOf(JsonElement body, int status) =>
        body.ValueKind == JsonValueKind.Object && body.TryGetProperty("error", out var e) && e.ValueKind == JsonValueKind.String
            ? e.GetString() ?? $"HTTP {status}" : $"HTTP {status}";

    public void Dispose() => _http.Dispose();
}
