using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using MeowRoom.Services;

namespace RoomAgent;

/// <summary>
/// 联机模块：单独提权跑，只负责「起隧道 / 找端口 / 发布地址」。
/// 启动器本体不提权，通过命名管道指挥这个进程。
/// 地址只有房主模式发布，而且必须隧道在跑、端口在监听、子网代理已建立。
/// </summary>
public static class Program
{
    // 启动器和模块之间的回环端口。用 TCP 而不是命名管道：提权进程建的管道，
    // 沙箱/受限令牌的启动器会被 ACL 拒绝；127.0.0.1 回环没有这层对象 ACL。
    private const int Port = 47831;

    private static readonly EasyTierService Tunnel = new();
    private static HttpClient Http = new();
    private static string _room = "";
    private static string _secret = "";
    private static string _api = "";
    private static string _token = "";
    private static string _edge = "";
    private static string _rendezvous = ""; // 只接受主程序验签后下发的地址
    private static int _lastPort;
    private static int _fixedPort;
    private static bool _expose;
    private static string _published = "";
    private static long _nextPublishTick;
    private static bool _warnedNoLan;
    private static StreamWriter? _out;

    private static Task? _portsTask;
    private static readonly string LogPath = Path.Combine(Path.GetTempPath(), "roomagent.log");

    private static void LogFile(string msg)
    {
        try { File.AppendAllText(LogPath, DateTime.Now.ToString("HH:mm:ss") + " " + msg + Environment.NewLine); } catch { }
    }

    public static async Task Main(string[] args)
    {
        var parentPid = 0;
        for (var i = 0; i < args.Length - 1; i++)
            if (args[i] == "--parent" && int.TryParse(args[i + 1], out var pp)) parentPid = pp;
        if (parentPid > 0) WatchParent(parentPid);

        // 控制口鉴权：启动器通过提权命令行传来一次性 token；没有 token 就不开口。
        var authToken = "";
        for (var i = 0; i < args.Length - 1; i++)
            if (args[i] == "--token") authToken = args[i + 1];
        if (authToken.Length < 32)
        {
            LogFile("no auth token, exit");
            return;
        }

        // 单实例：已经在跑就别再起一个（否则两个进程抢同一个端口）
        bool createdNew;
        var mutex = new Mutex(true, @"Global\MeowRoomAgentSingleV6", out createdNew);
        if (!createdNew)
        {
            LogFile("already running, exit");
            return;
        }
        LogFile("=== start v6 " + Environment.UserName + " admin=" + IsAdmin());

        var listener = new TcpListener(IPAddress.Loopback, Port);
        listener.Start();

        // 连过一次就常驻，客户端断开（关窗口/崩溃）后回到等待连接：
        // 关房再开不需要重新弹 UAC。但启动器整个退出时由父进程监视负责收尾。
        while (true)
        {
            TcpClient client;
            using (var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5)))
            {
                try { client = await listener.AcceptTcpClientAsync(cts.Token); }
                catch (OperationCanceledException) { LogFile("no client in 5min, exit"); return; }
            }

            using (client)
            {
                client.NoDelay = true;
                var stream = client.GetStream();
                using var reader = new StreamReader(stream, Encoding.UTF8, false, 1024, leaveOpen: true);

                // 第一句必须是 hello+token，3 秒内；不对就断开，不回任何内容
                string? first;
                try { first = await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(3)); }
                catch (Exception) { first = null; }
                if (!AuthOk(first, authToken))
                {
                    LogFile("rejected unauthenticated client");
                    continue;
                }
                _out = new StreamWriter(stream, new UTF8Encoding(false)) { AutoFlush = true };

                LogFile("tcp connected");
                Emit("log", "联机模块已就绪（管理员，v6）");
                _portsTask ??= Task.Run(LoopPortsAsync);

                while (true)
                {
                    var line = reader.ReadLine();
                    if (line is null) break;
                    try { Handle(line); } catch (Exception ex) { Emit("log", "模块出错：" + ex.Message); }
                }

                LogFile("client gone, back to waiting");
            }
        }
    }

    private static bool AuthOk(string? line, string token)
    {
        if (string.IsNullOrEmpty(line) || line.Length > 512) return false;
        try
        {
            using var doc = JsonDocument.Parse(line);
            var r = doc.RootElement;
            if (!r.TryGetProperty("cmd", out var c) || c.GetString() != "hello") return false;
            var got = Encoding.UTF8.GetBytes(r.TryGetProperty("token", out var t) ? t.GetString() ?? "" : "");
            var want = Encoding.UTF8.GetBytes(token);
            return got.Length == want.Length && CryptographicOperations.FixedTimeEquals(got, want);
        }
        catch { return false; }
    }

    private static void Handle(string line)
    {
        using var doc = JsonDocument.Parse(line);
        var root = doc.RootElement;
        var cmd = root.TryGetProperty("cmd", out var c) ? c.GetString() : "";

        switch (cmd)
        {
            case "ping":
                Emit("pong", "ok");
                break;

            case "start":
                _room = Str(root, "room");
                _secret = Str(root, "secret");
                _api = Str(root, "api");
                _token = Str(root, "token");
                var rendezvous = Str(root, "rendezvous");
                if (rendezvous.Length > 0) _rendezvous = rendezvous;
                if (_api.Length == 0 || _rendezvous.Length == 0)
                {
                    Emit("log", "隧道：未收到已验证的服务配置，已拒绝启动");
                    break;
                }
                _expose = root.TryGetProperty("expose", out var ex) && ex.ValueKind == JsonValueKind.True;
                _fixedPort = root.TryGetProperty("port", out var pe) && pe.TryGetInt32(out var pv) ? pv : 0;

                // 全局生效：把域名钉到测速选出的边缘 IP，本机其它程序（浏览器、验证码页）也跟着走
                _edge = Str(root, "edge");
                HostsPin.Clear();
                if (_edge.Length > 0 && Uri.TryCreate(_api, UriKind.Absolute, out var apiUri))
                    HostsPin.Pin(apiUri.Host, _edge);
                Http = MakeHttp(_edge);

                _published = "";
                _nextPublishTick = 0;
                _lastPort = 0;
                _warnedNoLan = false;

                Tunnel.Start(_room, _secret, _expose, _rendezvous, out var msg);
                Emit("log", "隧道：" + msg);
                // EasyTier 的输出已经由 EasyTierService 直接接管，不再 tail 日志文件

                if (!_expose)
                {
                    Emit("log", "加入端不发布自己的地址，等房主发布");
                }
                else if (Tunnel.MappedPrefix is null || Tunnel.ProxiedAddress is null)
                {
                    Emit("log", "没有可用的局域网网卡，地址发布不了");
                }
                else if (_fixedPort > 0 && !McPortScanner.IsListening(_fixedPort))
                {
                    Emit("log", $"端口 {_fixedPort} 现在没有在监听，等游戏里「对局域网开放」后会自动发布");
                }
                break;

            case "stop":
                Tunnel.Stop();
                _room = "";
                _secret = "";
                _expose = false;
                _fixedPort = 0;
                _published = "";
                _lastPort = 0;
                _warnedNoLan = false;
                HostsPin.Clear();
                Emit("log", "隧道已关闭");
                break;

            case "quit":
                Tunnel.Stop();
                HostsPin.Clear();
                Emit("log", "联机模块退出");
                Environment.Exit(0);
                break;
        }
    }

    private static async Task LoopPortsAsync()
    {
        while (true)
        {
            await Task.Delay(2000);
            try
            {
                // 端口由启动器选好传进来：扫 java、找监听都在启动器里做，不需要管理员
                var port = _fixedPort;
                if (port <= 0) { _lastPort = 0; continue; }

                if (!McPortScanner.IsListening(port)) { _lastPort = 0; continue; }
                if (_lastPort != port)
                {
                    _lastPort = port;
                    Emit("log", $"端口 {port} 正在监听");
                }

                if (!_expose || _room.Length != 6 || !Tunnel.IsRunning) continue;
                if (Tunnel.MappedPrefix is null || Tunnel.ProxiedAddress is null)
                {
                    if (!_warnedNoLan) { _warnedNoLan = true; Emit("log", "子网代理没有建立，地址发布跳过"); }
                    continue;
                }

                var addr = TunnelAddress.Build(port, Tunnel.ProxiedAddress, Tunnel.MappedPrefix);
                if (addr is null || addr == _published) continue;
                if (Environment.TickCount64 < _nextPublishTick) continue;

                await PublishAsync(addr);
            }
            catch { }
        }
    }

    /// <summary>启动器退出（或崩溃）时，模块跟着退出，不留后台提权进程。</summary>
    private static void WatchParent(int pid)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                using var p = System.Diagnostics.Process.GetProcessById(pid);
                await p.WaitForExitAsync();
            }
            catch { }
            LogFile("parent gone, exit");
            try { Tunnel.Stop(); } catch { }
            HostsPin.Clear();
            Environment.Exit(0);
        });
    }

    private static async Task PublishAsync(string addr)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, _api.TrimEnd('/') + "/api/room/addr");
            req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _token);
            req.Content = new StringContent(JsonSerializer.Serialize(new { roomCode = _room, addr }),
                Encoding.UTF8, "application/json");
            using var res = await Http.SendAsync(req);
            if (res.IsSuccessStatusCode)
            {
                _published = addr;
                Emit("addr", addr);
                Emit("log", "地址已发布：" + addr);
            }
            else
            {
                // 失败不标记成功，8 秒后重试
                _nextPublishTick = Environment.TickCount64 + 8000;
                Emit("log", $"地址发布失败：HTTP {(int)res.StatusCode}，稍后重试");
            }
        }
        catch (Exception ex)
        {
            _nextPublishTick = Environment.TickCount64 + 8000;
            Emit("log", "地址发布异常：" + ex.Message);
        }
    }

    private static string Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static void Emit(string ev, string msg)
    {
        LogFile($"{ev}: {msg}");
        try { _out?.WriteLine(JsonSerializer.Serialize(new { ev, msg })); } catch { }
    }

    private static async Task<bool> WaitAsync(NamedPipeServerStream server, TimeSpan timeout)
    {
        var task = server.WaitForConnectionAsync();
        var done = await Task.WhenAny(task, Task.Delay(timeout));
        if (done != task) return false;
        await task;
        return true;
    }

    private static bool IsAdmin()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(id)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private static CancellationTokenSource? _tailCts;

    /// <summary>EasyTier 自己写日志文件（提权进程无法重定向 stdout），把新增行回传给界面。</summary>
    private static void StartTunnelLogTail_Unused()
    {
        _tailCts?.Cancel();
        var dir = Tunnel.LogDir;
        if (string.IsNullOrEmpty(dir)) return;
        var cts = new CancellationTokenSource();
        _tailCts = cts;
        var lastLen = 0L;

        _ = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    var file = new DirectoryInfo(dir).GetFiles("*.log")
                        .OrderByDescending(f => f.LastWriteTimeUtc).FirstOrDefault();
                    if (file != null && file.Length > lastLen)
                    {
                        using var fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                        fs.Seek(lastLen, SeekOrigin.Begin);
                        using var sr = new StreamReader(fs);
                        string? line;
                        while ((line = await sr.ReadLineAsync()) != null)
                        {
                            // 只转发告警/错误：EasyTier 的 INFO 里全是 peer 心跳，会把事件列表刷屏
                            var text = line.Trim();
                            var noisy = text.Contains(" INFO ", StringComparison.Ordinal)
                                || text.Contains("DEBUG", StringComparison.OrdinalIgnoreCase);
                            if (!noisy && (text.Contains("ERROR", StringComparison.OrdinalIgnoreCase)
                                || text.Contains("WARN", StringComparison.OrdinalIgnoreCase)))
                                Emit("log", "EasyTier · " + (text.Length > 300 ? text[..300] + "…" : text));
                        }
                        lastLen = file.Length;
                    }
                }
                catch { }
                try { await Task.Delay(1500, cts.Token); } catch { break; }
            }
        }, cts.Token);
    }

    /// <summary>发布地址时也走选中的边缘 IP，别让提权进程再按系统 DNS 撞到被丢包的 IP。</summary>
    private static HttpClient MakeHttp(string edge)
    {
        if (edge.Length == 0) return new HttpClient { Timeout = TimeSpan.FromSeconds(15) };

        var handler = new SocketsHttpHandler
        {
            ConnectCallback = async (_, ct) =>
            {
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await socket.ConnectAsync(IPAddress.Parse(edge), 443, ct);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch { socket.Dispose(); throw; }
            }
        };
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
    }
}

/// <summary>
/// 联机模块运行期间把房间服务域名钉到测速选出的边缘 IP。
/// 这样浏览器、验证码 WebView2、其它客户端都不用再自己处理被丢包的 IP。
/// 退出时（stop / quit / 父进程消失）必须删掉，不留脏 hosts。
/// </summary>
internal static class HostsPin
{
    private const string Marker = "# meow-room-edge";
    private static readonly string HostsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

    // hosts 被设成只读时，管理员也写不进去（本机 hosts 就是 ReadOnly）
    private static void MakeWritable()
    {
        try
        {
            var attrs = File.GetAttributes(HostsPath);
            if ((attrs & FileAttributes.ReadOnly) != 0)
                File.SetAttributes(HostsPath, attrs & ~FileAttributes.ReadOnly);
        }
        catch { }
    }

    public static void Pin(string host, string ip)
    {
        try
        {
            MakeWritable();
            if (!File.Exists(HostsPath + ".meowbak")) File.Copy(HostsPath, HostsPath + ".meowbak", true);
            var lines = File.Exists(HostsPath)
                ? File.ReadAllLines(HostsPath).Where(l => !l.Contains(Marker)).ToList()
                : new List<string>();
            lines.Add($"{ip} {host} {Marker}");
            File.WriteAllLines(HostsPath, lines);
            Flush();
            LogFile($"hosts pinned {host} -> {ip}");
        }
        catch (Exception ex) { LogFile("系统 hosts 被安全软件保护，全局映射没生效；本程序内部请求仍走固定线路（" + ex.GetType().Name + "）"); }
    }

    public static void Clear()
    {
        try
        {
            MakeWritable();
            if (!File.Exists(HostsPath)) return;
            var lines = File.ReadAllLines(HostsPath);
            if (!lines.Any(l => l.Contains(Marker))) return;
            File.WriteAllLines(HostsPath, lines.Where(l => !l.Contains(Marker)));
            Flush();
            LogFile("hosts pin cleared");
        }
        catch (Exception ex) { LogFile("hosts clear failed: " + ex.Message); }
    }

    private static void Flush()
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("ipconfig", "/flushdns")
            {
                CreateNoWindow = true,
                UseShellExecute = false
            });
        }
        catch { }
    }

    private static void LogFile(string msg)
    {
        try
        {
            var path = Path.Combine(Path.GetTempPath(), "roomagent.log");
            File.AppendAllText(path, DateTime.Now.ToString("HH:mm:ss") + " " + msg + Environment.NewLine);
        }
        catch { }
    }
}
