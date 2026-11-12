using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MeowRoom.Services;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;

// 自测：全部通过返回 0，有失败返回 1。
var failed = 0;
void T(string name, bool ok, string info = "")
{
    Console.WriteLine((ok ? "PASS " : "FAIL ") + name + (info.Length > 0 ? " | " + info : ""));
    if (!ok) failed++;
}

// ───────────── 0. 联机总开关：默认关闭时，模块不产生任何网络请求、不拉起提权代理 ─────────────
{
    T("switch: default is off", !OnlineSwitch.Enabled);
    T("switch: config fetch refused while off",
        !await RemoteConfig.EnsureAsync() && RemoteConfig.LastError == OnlineSwitch.DisabledMessage, RemoteConfig.LastError);
    using var api0 = new RoomApiClient(() => "");
    var (s0, _) = await api0.CallAsync(HttpMethod.Get, "/api/health", quiet: true);
    T("switch: api call makes no request while off", s0 == 0);
    using var agent0 = new AgentClient();
    T("switch: agent is not started (no UAC) while off", !await agent0.StartAsync("123456", new string('d', 32), false, "tok"));
    await new RoomSocket(() => "").RunAsync("123456", CancellationToken.None);
    T("switch: socket returns immediately while off", true);
    OnlineSwitch.Enabled = true;   // 后面的测试需要联机功能开着
}

// ───────────── 1. 云下发配置：验签 / 过期 / 篡改 / 清单格式 ─────────────
{
    var sk = new byte[Ed25519.SecretKeySize];
    var pk = new byte[Ed25519.PublicKeySize];
    Ed25519.GeneratePrivateKey(new SecureRandom(), sk);
    Ed25519.GeneratePublicKey(sk, 0, pk, 0);
    byte[]? Keys(string kid) => kid == "k1" ? pk : null;

    const long now = 1_800_000_000;
    string Sign(string payload, string kid = "k1")
    {
        var msg = Encoding.UTF8.GetBytes(payload);
        var sig = new byte[Ed25519.SignatureSize];
        Ed25519.Sign(sk, 0, msg, 0, msg.Length, sig, 0);
        return JsonSerializer.Serialize(new { payload, sig = Convert.ToBase64String(sig), kid });
    }
    string Payload(long issued = now, long expires = now + 3600, string room = "https://rooms.example.test",
        string relay = "tcp://relay.example.test:11010", object? easytier = null, int version = 1) =>
        JsonSerializer.Serialize(new { version, issuedAt = issued, expiresAt = expires, roomBase = room, relay, easytier });

    var sha = new string('a', 64);
    var good = Sign(Payload(easytier: new { files = new[] { new { name = "easytier-core.exe", sha256 = sha, required = true } } }));
    var cfg = RemoteConfig.VerifyEnvelope(good, Keys, now);
    T("config: valid envelope verifies", cfg is not null && cfg.RoomBase == "https://rooms.example.test"
        && cfg.EasyTierFiles.Length == 1 && cfg.EasyTierFiles[0].Sha256 == sha);
    T("config: expired rejected", RemoteConfig.VerifyEnvelope(Sign(Payload(expires: now - 3600)), Keys, now) is null);
    T("config: not-yet-valid rejected", RemoteConfig.VerifyEnvelope(Sign(Payload(issued: now + 7200, expires: now + 9000)), Keys, now) is null);
    T("config: clock skew within 5min tolerated", RemoteConfig.VerifyEnvelope(Sign(Payload(issued: now + 200)), Keys, now) is not null);
    T("config: unknown kid rejected", RemoteConfig.VerifyEnvelope(Sign(Payload(), "k9"), Keys, now) is null);
    T("config: wrong version rejected", RemoteConfig.VerifyEnvelope(Sign(Payload(version: 2)), Keys, now) is null);
    T("config: tampered payload rejected", RemoteConfig.VerifyEnvelope(good.Replace("rooms.example.test", "evil.example.test"), Keys, now) is null);
    T("config: garbage rejected", RemoteConfig.VerifyEnvelope("{not json", Keys, now) is null);
    T("config: http roomBase rejected in signed config", RemoteConfig.VerifyEnvelope(Sign(Payload(room: "http://rooms.example.test")), Keys, now) is null);
    T("config: malformed relay rejected", RemoteConfig.VerifyEnvelope(Sign(Payload(relay: "relay.example.test")), Keys, now) is null);

    string WithAccount(string a) => Sign(JsonSerializer.Serialize(new
    {
        version = 1, issuedAt = now, expiresAt = now + 3600,
        roomBase = "https://rooms.example.test", relay = "tcp://relay.example.test:11010", accountBase = a,
    }));
    var withAcct = RemoteConfig.VerifyEnvelope(WithAccount("https://acct.example.test/"), Keys, now);
    T("config: accountBase parsed (trailing slash trimmed)", withAcct is not null && withAcct.AccountBase == "https://acct.example.test");
    T("config: accountBase is optional (empty when absent)", cfg is not null && cfg.AccountBase == "");
    T("config: http accountBase rejected in signed config", RemoteConfig.VerifyEnvelope(WithAccount("http://acct.example.test"), Keys, now) is null);
    T("config: garbage accountBase rejected", RemoteConfig.VerifyEnvelope(WithAccount("not a url"), Keys, now) is null);
    T("config: path in component name rejected",
        RemoteConfig.VerifyEnvelope(Sign(Payload(easytier: new { files = new[] { new { name = "..\\evil.exe", sha256 = sha, required = true } } })), Keys, now) is null);
    T("config: bad component hash rejected",
        RemoteConfig.VerifyEnvelope(Sign(Payload(easytier: new { files = new[] { new { name = "easytier-core.exe", sha256 = "xyz", required = true } } })), Keys, now) is null);
}

// ───────────── 2. 边缘 IP 校验（写 hosts 前用） ─────────────
T("edge: cloudflare ip accepted", EdgeLocator.IsCloudflareIp("104.17.0.1") && EdgeLocator.IsCloudflareIp("162.159.140.1"));
T("edge: non-cloudflare / loopback / garbage rejected",
    !EdgeLocator.IsCloudflareIp("8.8.8.8") && !EdgeLocator.IsCloudflareIp("127.0.0.1")
    && !EdgeLocator.IsCloudflareIp("not-an-ip") && !EdgeLocator.IsCloudflareIp(null) && !EdgeLocator.IsCloudflareIp("::1"));

// ───────────── 3. EasyTier 组件：哈希校验 + 复制到受保护目录 ─────────────
{
    var tmp = Path.Combine(Path.GetTempPath(), "meowroom-selftest-" + Guid.NewGuid().ToString("N")[..8]);
    var src = Path.Combine(tmp, "src");
    var dest = Path.Combine(tmp, "dest");
    Directory.CreateDirectory(src);
    File.WriteAllBytes(Path.Combine(src, "easytier-core.exe"), Encoding.UTF8.GetBytes("fake-core-binary"));
    File.WriteAllBytes(Path.Combine(src, "wintun.dll"), Encoding.UTF8.GetBytes("fake-wintun"));
    string H(string f) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(src, f)))).ToLowerInvariant();

    var files = new List<ComponentFile>
    {
        new("easytier-core.exe", H("easytier-core.exe"), true),
        new("wintun.dll", H("wintun.dll"), true),
        new("Packet.dll", new string('b', 64), false),   // 可选组件，来源里没有
    };
    var core = EasyTierService.PrepareComponents(src, files, out var err, dest);
    T("components: matching hashes -> copied to dest", core is not null && File.Exists(core) && core.StartsWith(dest)
        && File.Exists(Path.Combine(Path.GetDirectoryName(core)!, "wintun.dll")), err);
    T("components: optional missing file is skipped", core is not null && !File.Exists(Path.Combine(Path.GetDirectoryName(core)!, "Packet.dll")));

    var wrong = new List<ComponentFile> { new("easytier-core.exe", new string('0', 64), true) };
    T("components: wrong hash rejected", EasyTierService.PrepareComponents(src, wrong, out var e2, dest) is null && e2.Contains("哈希"), e2);

    File.WriteAllBytes(Path.Combine(src, "easytier-core.exe"), Encoding.UTF8.GetBytes("TAMPERED-core"));
    var tampered = EasyTierService.PrepareComponents(src, files, out var e3, Path.Combine(tmp, "dest2"));
    T("components: tampered source file rejected", tampered is null, e3);

    T("components: empty manifest rejected", EasyTierService.PrepareComponents(src, new List<ComponentFile>(), out _, dest) is null);
    T("components: manifest without core rejected",
        EasyTierService.PrepareComponents(src, new List<ComponentFile> { new("wintun.dll", H("wintun.dll"), true) }, out _, dest) is null);
    T("components: path traversal in name rejected",
        EasyTierService.PrepareComponents(src, new List<ComponentFile>
        { new("easytier-core.exe", H("wintun.dll"), true), new("..\\evil.dll", new string('c', 64), true) }, out _, dest) is null);

    // Start 的前置拒绝（不会真起进程）
    Environment.SetEnvironmentVariable("MEOW_EASYTIER", Path.Combine(src, "easytier-core.exe"));
    var svc = new EasyTierService();
    T("tunnel: empty secret refused (no fallback to room code)",
        !svc.Start("123456", "", false, "tcp://relay.example.test:11010", files, out var m1) && m1.Contains("密钥"), m1);
    T("tunnel: missing manifest refused",
        !svc.Start("123456", new string('d', 32), false, "tcp://relay.example.test:11010", new List<ComponentFile>(), out var m2), m2);
    T("tunnel: bad room code refused",
        !svc.Start("12 34;calc", new string('d', 32), false, "tcp://relay.example.test:11010", files, out var m3), m3);
    T("tunnel: bad relay refused",
        !svc.Start("123456", new string('d', 32), false, "tcp://x y:1", files, out var m4), m4);
    try { Directory.Delete(tmp, true); } catch { }
}

// ───────────── 4. RoomApiClient：本地假服务 ─────────────
{
    var port = 18931;
    var counts = new Dictionary<string, int>();
    var cfgPath = Path.Combine(Path.GetTempPath(), "meowroom-selftest-cfg.json");
    const int acctPort = 18932;
    File.WriteAllText(cfgPath, "{\"version\":1,\"issuedAt\":0,\"expiresAt\":9999999999,\"roomBase\":\"http://127.0.0.1:" + port
        + "\",\"relay\":\"tcp://127.0.0.1:11010\",\"accountBase\":\"http://127.0.0.1:" + acctPort + "\"}");
    Environment.SetEnvironmentVariable("MEOW_DEV_CONFIG", cfgPath);

    var l = new HttpListener();
    l.Prefixes.Add($"http://127.0.0.1:{port}/");
    l.Start();
    _ = Task.Run(async () =>
    {
        while (true)
        {
            HttpListenerContext ctx;
            try { ctx = await l.GetContextAsync(); } catch { return; }
            var p = ctx.Request.Url!.AbsolutePath;
            int n;
            lock (counts) { counts[p] = counts.GetValueOrDefault(p) + 1; n = counts[p]; }
            if (p == "/api/login" && n == 1) { ctx.Response.Abort(); continue; }
            if (p == "/api/room/create" && n == 1) { ctx.Response.Abort(); continue; }
            if (p == "/api/room/info") ctx.Response.StatusCode = 401;
            var b = Encoding.UTF8.GetBytes("{\"ok\":true}");
            ctx.Response.OutputStream.Write(b, 0, b.Length);
            ctx.Response.Close();
        }
    });

    var token = "tok";
    var expired = 0;
    using var api = new RoomApiClient(() => token);
    api.SessionExpired += () => Interlocked.Increment(ref expired);

    var (s1, _) = await api.CallAsync(HttpMethod.Post, "/api/login", new { }, quiet: true);
    T("api: dropped login is auto-retried -> 200", s1 == 200 && counts["/api/login"] == 2, $"status={s1} hits={counts["/api/login"]}");
    var (s2, _) = await api.CallAsync(HttpMethod.Post, "/api/room/create", new { }, quiet: true);
    T("api: dropped create is NOT retried", s2 == 0 && counts["/api/room/create"] == 1, $"status={s2} hits={counts["/api/room/create"]}");
    var (s3, _) = await api.CallAsync(HttpMethod.Get, "/api/room/info?code=1", quiet: true);
    var (s3b, _) = await api.CallAsync(HttpMethod.Get, "/api/room/info?code=1", quiet: true);
    T("api: 401 raises SessionExpired exactly once", s3 == 401 && s3b == 401 && expired == 1, $"expired={expired}");
    api.ResetSession();
    await api.CallAsync(HttpMethod.Get, "/api/room/info?code=1", quiet: true);
    T("api: after ResetSession it can raise again", expired == 2);
    token = ""; expired = 0; api.ResetSession();
    await api.CallAsync(HttpMethod.Get, "/api/room/info?code=1", quiet: true);
    T("api: 401 without a login token does not raise", expired == 0);
    T("api: per-endpoint timeouts", RoomApiClient.TimeoutFor("/api/room/create").TotalSeconds == 45
        && RoomApiClient.TimeoutFor("/api/health").TotalSeconds == 10 && RoomApiClient.TimeoutFor("/api/login").TotalSeconds == 20);

    // ---- 账号服务客户端：进程内假账号服务（含 WebSocket）----
    const string GoodTok = "tok-good";
    const string SrvId = "00112233445566778899aabbccddeeff";
    string? lastVerifyBody = null;
    string? lastReplyBody = null;
    var revoked = false;
    var verifyCalls = 0;
    var acct = new HttpListener();
    acct.Prefixes.Add($"http://127.0.0.1:{acctPort}/");
    acct.Start();
    _ = Task.Run(async () =>
    {
        while (true)
        {
            HttpListenerContext c;
            try { c = await acct.GetContextAsync(); } catch { return; }
            _ = Task.Run(async () =>
            {
                var path = c.Request.Url!.AbsolutePath;
                var auth = c.Request.Headers["Authorization"] ?? "";
                async Task Reply(int code, string body)
                {
                    c.Response.StatusCode = code;
                    c.Response.ContentType = "application/json";
                    var b = Encoding.UTF8.GetBytes(body);
                    await c.Response.OutputStream.WriteAsync(b);
                    c.Response.Close();
                }
                if (path == "/auth/challenge") { await Reply(200, "{\"ok\":true,\"serverId\":\"" + SrvId + "\"}"); return; }
                if (path == "/auth/verify")
                {
                    Interlocked.Increment(ref verifyCalls);
                    using var rd = new StreamReader(c.Request.InputStream);
                    lastVerifyBody = await rd.ReadToEndAsync();
                    var vb = JsonDocument.Parse(lastVerifyBody).RootElement;
                    if (vb.TryGetProperty("serverId", out var vsid) && vsid.GetString() == SrvId
                        && vb.TryGetProperty("signature", out var vsig) && vsig.GetString() == "sig-ok")
                        await Reply(200, "{\"ok\":true,\"token\":\"" + GoodTok + "\",\"uuid\":\"" + new string('a', 32) + "\",\"name\":\"Alice_A\",\"exp\":9999999999999,\"developer\":true}");
                    else
                        await Reply(401, "{\"ok\":false,\"error\":\"bad-proof\"}");
                    return;
                }
                if (path == "/invite")
                {
                    if (auth != "Bearer " + GoodTok || revoked) await Reply(401, "{\"ok\":false,\"error\":\"unauthorized\"}");
                    else await Reply(200, "{\"ok\":true,\"delivered\":true}");
                    return;
                }
                if (path == "/invite/reply")
                {
                    using var rr = new StreamReader(c.Request.InputStream);
                    lastReplyBody = await rr.ReadToEndAsync();
                    if (auth != "Bearer " + GoodTok || revoked) await Reply(401, "{\"ok\":false,\"error\":\"unauthorized\"}");
                    else if (lastReplyBody.Contains("\"nobody\"")) await Reply(404, "{\"ok\":false,\"error\":\"no-pending\"}");
                    else await Reply(200, "{\"ok\":true,\"delivered\":true}");
                    return;
                }
                if (path == "/ws" && c.Request.IsWebSocketRequest)
                {
                    if (auth != "Bearer " + GoodTok || revoked) { c.Response.StatusCode = 401; c.Response.Close(); return; }
                    var wsCtx = await c.AcceptWebSocketAsync(null);
                    var ws = wsCtx.WebSocket;
                    await ws.SendAsync(Encoding.UTF8.GetBytes("{\"type\":\"hello\"}"), WebSocketMessageType.Text, true, CancellationToken.None);
                    await ws.SendAsync(Encoding.UTF8.GetBytes("{\"type\":\"invite\",\"from\":{\"uuid\":\"" + new string('b', 32) + "\",\"name\":\"Bob_B\"},\"roomCode\":\"123456\",\"ts\":42}"),
                        WebSocketMessageType.Text, true, CancellationToken.None);
                    await ws.SendAsync(Encoding.UTF8.GetBytes("{\"type\":\"invite_reply\",\"from\":{\"uuid\":\"" + new string('b', 32) + "\",\"name\":\"Bob_B\"},\"accepted\":true,\"ts\":43}"),
                        WebSocketMessageType.Text, true, CancellationToken.None);
                    var buf = new byte[1024];
                    try
                    {
                        while (ws.State == WebSocketState.Open)
                        {
                            var r = await ws.ReceiveAsync(buf, CancellationToken.None);
                            if (r.MessageType == WebSocketMessageType.Close) break;
                            if (Encoding.UTF8.GetString(buf, 0, r.Count) == "ping")
                                await ws.SendAsync(Encoding.UTF8.GetBytes("{\"type\":\"pong\"}"), WebSocketMessageType.Text, true, CancellationToken.None);
                        }
                    }
                    catch { }
                    return;
                }
                await Reply(404, "{}");
            });
        }
    });

    using var svc = new AccountService();
    var (earlyOk, _, earlyMsg) = await svc.InviteAsync(new string('b', 32));
    T("account: invite before login is refused", !earlyOk && earlyMsg.Contains("登录"), earlyMsg);

    var proveCalls = 0;
    var (noProofOk, noProofMsg) = await svc.LoginAsync("Alice_A", (_, _) => { proveCalls++; return Task.FromResult<LoginProof?>(null); });
    T("account: no proof from the host -> login refused, verify never called", !noProofOk && proveCalls == 1 && verifyCalls == 0, noProofMsg);

    var (badOk, badMsg) = await svc.LoginAsync("Alice_A", (_, _) => Task.FromResult<LoginProof?>(new LoginProof(new string('a', 32), "AAAA", 1, "BBBB", "sig-bad")));
    T("account: server rejecting the proof -> login refused with the server's reason", !badOk && badMsg.Contains("bad-proof"), badMsg);

    string? seenServerId = null;
    var (loginOk, loginMsg) = await svc.LoginAsync("Alice_A", (sid, _) =>
    {
        seenServerId = sid;
        return Task.FromResult<LoginProof?>(new LoginProof(new string('a', 32), "PUBKEY", 1234567890123, "CERTSIG", "sig-ok"));
    });
    T("account: login hands the server's challenge to the host's prover", seenServerId == SrvId, seenServerId ?? "null");
    var sent = JsonDocument.Parse(lastVerifyBody ?? "{}").RootElement;
    T("account: verify request carries uuid / publicKey / expiresAtMs / certSignature / signature and no token",
        sent.TryGetProperty("uuid", out var su) && su.GetString() == new string('a', 32)
        && sent.GetProperty("publicKey").GetString() == "PUBKEY" && sent.GetProperty("expiresAtMs").GetInt64() == 1234567890123
        && sent.GetProperty("certSignature").GetString() == "CERTSIG" && sent.GetProperty("signature").GetString() == "sig-ok"
        && !(lastVerifyBody ?? "").Contains("ccessToken", StringComparison.OrdinalIgnoreCase));
    T("account: login succeeds, session carries authoritative uuid/name/developer",
        loginOk && svc.Session is { } ss && ss.Uuid == new string('a', 32) && ss.Name == "Alice_A" && ss.Developer && svc.IsLoggedIn, loginMsg);

    var (invOk, invDelivered, _) = await svc.InviteAsync(new string('b', 32), "123456");
    T("account: invite with session -> delivered", invOk && invDelivered);

    InviteEvent? gotInvite = null;
    InviteReplyEvent? gotReply = null;
    svc.Invite += e => gotInvite = e;
    svc.InviteReply += e => gotReply = e;
    using var pushCts = new CancellationTokenSource();
    var pushTask = svc.RunPushAsync(pushCts.Token);
    for (var i = 0; i < 40 && gotInvite is null; i++) await Task.Delay(100);
    T("account: push channel delivers an invite event", gotInvite is { } g && g.FromName == "Bob_B" && g.RoomCode == "123456" && g.FromUuid == new string('b', 32) && g.Timestamp == 42,
        gotInvite is null ? "nothing received" : $"{gotInvite.FromName}/{gotInvite.RoomCode}");
    for (var i = 0; i < 40 && gotReply is null; i++) await Task.Delay(100);
    T("account: push channel delivers an invite reply event", gotReply is { } gr && gr.FromName == "Bob_B" && gr.Accepted && gr.FromUuid == new string('b', 32) && gr.Timestamp == 43,
        gotReply is null ? "nothing received" : $"{gotReply.FromName}/{gotReply.Accepted}");
    pushCts.Cancel();
    try { await pushTask; } catch (OperationCanceledException) { }

    var (repOk, repDelivered, _) = await svc.ReplyInviteAsync(new string('b', 32), true);
    T("account: reply sends toUuid + accepted and reports delivered", repOk && repDelivered && (lastReplyBody ?? "").Contains("\"accepted\":true") && (lastReplyBody ?? "").Contains(new string('b', 32)), lastReplyBody ?? "null");
    var (rej, _, rejMsg) = await svc.ReplyInviteAsync("nobody", false);
    T("account: server refusing the reply surfaces its reason", !rej && rejMsg.Contains("no-pending"), rejMsg);

    // 服务端撤销会话：再连推送通道会被 401 拒绝 -> 触发 SessionExpired，并清掉本地会话
    revoked = true;
    var acctExpired = 0;
    svc.SessionExpired += () => Interlocked.Increment(ref acctExpired);
    using var pushCts2 = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    await svc.RunPushAsync(pushCts2.Token);
    T("account: 401 on the push channel -> SessionExpired once, session cleared", acctExpired == 1 && !svc.IsLoggedIn, $"expired={acctExpired} loggedIn={svc.IsLoggedIn}");
    acct.Stop();
    l.Stop();
    Environment.SetEnvironmentVariable("MEOW_DEV_CONFIG", null);
}

// ───────────── 5.（可选）RoomAgent 控制口 token 握手：--agent <RoomAgent.dll> ─────────────
var agentIdx = Array.IndexOf(args, "--agent");
if (agentIdx >= 0 && agentIdx + 1 < args.Length)
{
    var dll = args[agentIdx + 1];
    var tok = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    var psi = new ProcessStartInfo("dotnet", $"\"{dll}\" --token {tok}") { UseShellExecute = false, CreateNoWindow = true };
    using var agent = Process.Start(psi)!;
    await Task.Delay(3000);

    async Task<string> Probe(string? hello)
    {
        using var c = new TcpClient();
        await c.ConnectAsync(IPAddress.Loopback, 47831);
        var s = c.GetStream();
        if (hello is not null) await s.WriteAsync(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { cmd = "hello", token = hello }) + "\n"));
        await s.WriteAsync(Encoding.UTF8.GetBytes("{\"cmd\":\"ping\"}\n"));
        var sb = new StringBuilder();
        var buf = new byte[1024];
        using var cts = new CancellationTokenSource(2500);
        try
        {
            while (true)
            {
                var n = await s.ReadAsync(buf, cts.Token);
                if (n == 0) break;
                sb.Append(Encoding.UTF8.GetString(buf, 0, n));
            }
        }
        catch (OperationCanceledException) { }
        catch (IOException) { }
        return sb.ToString();
    }

    try
    {
        T("agent: wrong token gets no reply", (await Probe(new string('z', 64))).Length == 0);
        T("agent: no hello gets no reply", (await Probe(null)).Length == 0);
        T("agent: correct token gets pong", (await Probe(tok)).Contains("pong"));
    }
    finally { try { agent.Kill(true); } catch { } }
}
else Console.WriteLine("SKIP agent handshake test (pass --agent <RoomAgent.dll> to run it)");

Console.WriteLine(failed == 0 ? "ALL PASS" : $"{failed} FAILED");
return failed == 0 ? 0 : 1;
