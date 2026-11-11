using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
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
    File.WriteAllText(cfgPath, "{\"version\":1,\"issuedAt\":0,\"expiresAt\":9999999999,\"roomBase\":\"http://127.0.0.1:" + port
        + "\",\"relay\":\"tcp://127.0.0.1:11010\"}");
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
