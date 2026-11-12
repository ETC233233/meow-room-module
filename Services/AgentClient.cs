using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace MeowRoom.Services;

/// <summary>
/// 和独立的联机模块（RoomAgent，自带管理员清单）通信。
/// 启动器本体不提权，管道里下指令：start / stop / ping。
/// 模块只在点「开放」或「加入」时启动一次，之后复用；启动器退出，模块跟着退出。
/// </summary>
public sealed class AgentClient : IDisposable
{
    // 提权进程建命名管道时，沙箱/受限令牌的启动器会被 ACL 挡在门外（拒绝访问），
    // 改用只绑 127.0.0.1 的 TCP：本机回环连接不经过对象 ACL。
    private const int Port = 47831;
    private TcpClient? _tcp;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private bool _connectErrorLogged;

    // 一次性随机 token：只通过提权启动的命令行交给模块（非管理员进程读不到管理员进程的命令行），
    // 连上后第一句必须是 hello+token，否则模块直接断开。别的进程即使连上 47831 也驱动不了模块。
    private readonly string _token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    // 端口有人在听但握手不通过：多半是别的启动器进程拉起的模块
    private bool _foreignAgent;

    public event Action<string>? Log;
    public event Action<string>? Addr;

    public bool IsConnected => _tcp is { Connected: true };

    private async Task<bool> TryConnectAsync(int ms, bool quiet = false)
    {
        var tcp = new TcpClient();
        try
        {
            using var cts = new CancellationTokenSource(ms);
            await tcp.ConnectAsync(IPAddress.Loopback, Port, cts.Token);
            tcp.NoDelay = true;
            var stream = tcp.GetStream();
            var reader = new StreamReader(stream, Encoding.UTF8);
            var writer = new StreamWriter(stream, new UTF8Encoding(false)) { AutoFlush = true };

            // 握手：hello(token) + ping，等模块回 pong；超时或被断开说明 token 不对
            await writer.WriteLineAsync(JsonSerializer.Serialize(new { cmd = "hello", token = _token }));
            await writer.WriteLineAsync(JsonSerializer.Serialize(new { cmd = "ping" }));
            var authed = false;
            try
            {
                using var hs = new CancellationTokenSource(1500);
                while (await reader.ReadLineAsync(hs.Token) is { } line)
                    if (line.Contains("\"pong\"", StringComparison.Ordinal)) { authed = true; break; }
            }
            catch (OperationCanceledException) { }
            catch (IOException) { }
            if (!authed)
            {
                tcp.Dispose();
                _foreignAgent = true;
                return false;
            }

            _foreignAgent = false;
            _tcp = tcp;
            _reader = reader;
            _writer = writer;
            _connectErrorLogged = false;
            _ = Task.Run(ReadLoopAsync);
            return true;
        }
        catch (Exception ex)
        {
            // 失败要显式释放，别把半开的连接留着
            tcp.Dispose();
            if (!quiet && !_connectErrorLogged)
            {
                _connectErrorLogged = true;
                Log?.Invoke("连接联机模块失败：" + ex.Message);
            }
            return false;
        }
    }

    /// <summary>
    /// 连上已有的模块；没有就提权拉起一个。整个流程最多等 2 分钟（用户要过 UAC）。
    /// 只有建隧道需要管理员，扫端口之类的事情都在启动器里做，不经过这里。
    /// </summary>
    public async Task<bool> EnsureAsync(int waitMs = 120000)
    {
        // 联机总开关没开：不连也不拉起提权代理（不会弹 UAC）
        if (!OnlineSwitch.Enabled) { Log?.Invoke(OnlineSwitch.DisabledMessage); return false; }
        if (IsConnected) return true;

        // 模块可能还活着（刚关房、还没退），先连一下，能复用就不要再弹 UAC
        if (await TryConnectAsync(800, quiet: true)) return true;
        if (_foreignAgent)
        {
            Log?.Invoke("联机模块已经在运行，但不是这个启动器拉起的（握手没通过）。请先关掉另一个启动器或结束 RoomAgent 进程后重试。");
            return false;
        }

        var exe = ResolveAgentPath();
        if (exe is null) { Log?.Invoke("找不到联机模块 RoomAgent.exe"); return false; }

        Log?.Invoke("正在请求管理员权限（只有建隧道需要）…");
        Process? proc;
        try
        {
            // 把启动器 PID 传过去：启动器退出，模块自己退出，不留后台提权进程
            proc = Process.Start(new ProcessStartInfo(exe)
            {
                UseShellExecute = true,
                Verb = "runas",
                Arguments = $"--parent {Environment.ProcessId} --token {_token}"
            });
        }
        catch (Exception ex)
        {
            Log?.Invoke("没有拿到管理员权限，联机没法建立：" + ex.Message);
            return false;
        }

        var deadline = Environment.TickCount64 + waitMs;
        while (Environment.TickCount64 < deadline)
        {
            // 不要用 proc.HasExited 提前判死：runas 返回的往往是提权代理进程，
            // 它把真正的模块拉起来后自己就退了，HasExited 立刻为 true。只看管道通没通。
            if (await TryConnectAsync(1500)) return true;
            await Task.Delay(400);
        }

        Log?.Invoke("等了 2 分钟还是连不上联机模块");
        return false;
    }

    /// <summary>
    /// 让提权代理起隧道。注意：房间服务地址、中继、EasyTier 组件哈希<b>不由宿主传</b>，
    /// 提权代理自己拉取并验签配置（见 RemoteConfig），宿主传了也没用——这样宿主被攻破也没法把管理员进程指到别处。
    /// </summary>
    public async Task<bool> StartAsync(string room, string secret, bool expose, string token,
        int port = 0, string edge = "")
    {
        if (!await EnsureAsync()) return false;
        return Send(new { cmd = "start", room, secret, expose, token, port, edge });
    }

    public void Stop() => Send(new { cmd = "stop" });

    private bool Send(object payload)
    {
        try
        {
            if (_writer is null) { Log?.Invoke("联机模块还没连上"); return false; }
            _writer.WriteLine(JsonSerializer.Serialize(payload));
            return true;
        }
        catch (Exception ex)
        {
            Log?.Invoke("和联机模块通信失败：" + ex.Message);
            return false;
        }
    }

    private async Task ReadLoopAsync()
    {
        try
        {
            while (_reader is not null)
            {
                var line = await _reader.ReadLineAsync();
                if (line is null) break;
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;
                var ev = root.TryGetProperty("ev", out var e) ? e.GetString() : "";
                var msg = root.TryGetProperty("msg", out var m) ? m.GetString() ?? "" : "";
                if (ev == "addr") Addr?.Invoke(msg);
                else if (ev != "pong") Log?.Invoke(msg);
            }
        }
        catch { }
    }

    /// <summary>
    /// 找最新编译的那份 RoomAgent：优先 exe 同级（发行包），
    /// 其次 out/、bin/x64/{Debug,Release}，按修改时间取最新，避免跑到旧二进制。
    /// </summary>
    private static string? ResolveAgentPath()
    {
        var env = Environment.GetEnvironmentVariable("MEOW_AGENT");
        if (!string.IsNullOrWhiteSpace(env) && File.Exists(env)) return env;

        var candidates = new List<string>();
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
        {
            candidates.Add(Path.Combine(dir.FullName, "RoomAgent.exe"));
            candidates.Add(Path.Combine(dir.FullName, "RoomAgent", "out", "RoomAgent.exe"));
            candidates.Add(Path.Combine(dir.FullName, "RoomAgent", "bin", "x64", "Debug", "net8.0-windows", "RoomAgent.exe"));
            candidates.Add(Path.Combine(dir.FullName, "RoomAgent", "bin", "x64", "Release", "net8.0-windows", "RoomAgent.exe"));
            candidates.Add(Path.Combine(dir.FullName, "RoomAgent", "bin", "Debug", "net8.0-windows", "RoomAgent.exe"));
            candidates.Add(Path.Combine(dir.FullName, "RoomAgent", "bin", "Release", "net8.0-windows", "RoomAgent.exe"));
        }

        return candidates
            .Where(File.Exists)
            .Select(p => new FileInfo(p))
            .OrderByDescending(f => f.LastWriteTimeUtc)
            .Select(f => f.FullName)
            .FirstOrDefault();
    }

    public void Dispose()
    {
        try { _tcp?.Dispose(); } catch { }
    }
}
