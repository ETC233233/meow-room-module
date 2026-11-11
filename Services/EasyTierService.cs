using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace MeowRoom.Services;

/// <summary>
/// 拉起 easytier-core（需要 TUN，所以由已提权的 RoomAgent 来调用；主程序本身不提权）。
/// 建房端带子网代理把自家局域网暴露出去，加入端不做代理。
/// </summary>
public sealed class EasyTierService : IDisposable
{
    private readonly object _gate = new();
    private Process? _proc;
    private string _room = "";
    private string _secret = "";
    private bool _expose;

    private static readonly Regex RoomShape = new("^[A-Za-z0-9]{4,16}$", RegexOptions.Compiled);
    private static readonly Regex SecretShape = new("^[A-Za-z0-9_\\-]{8,128}$", RegexOptions.Compiled);
    private static readonly Regex RelayShape = new(@"^tcp://[A-Za-z0-9.\-]+:\d{2,5}$", RegexOptions.Compiled);

    public bool IsRunning => _proc is { HasExited: false };

    /// <summary>映射到隧道里的目标网段前缀，只有房主模式才有值。</summary>
    public string? MappedPrefix { get; private set; }

    /// <summary>被代理的那块局域网网卡地址；发布地址时必须用它，不能再自己挑一块。</summary>
    public IPAddress? ProxiedAddress { get; private set; }

    public string? ProxiedCidr { get; private set; }

    public string? LogDir { get; private set; }

    public event Action<string>? Log;

    /// <summary>EasyTier 的位置；可用环境变量 MEOW_EASYTIER 覆盖。EasyTier 本身不随本模块分发，需自行放置。</summary>
    public static string? ResolveCorePath()
    {
        var env = Environment.GetEnvironmentVariable("MEOW_EASYTIER");
        if (!string.IsNullOrWhiteSpace(env) && File.Exists(env)) return env;

        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 8 && dir != null; i++, dir = dir.Parent)
        {
            var p = Path.Combine(dir.FullName, "easytier", "easytier-windows-x86_64", "easytier-core.exe");
            if (File.Exists(p)) return p;
        }
        return null;
    }

    /// <summary>当前活动网卡的局域网网段，例如 192.168.1.0/24。</summary>
    public static string? DetectLanCidr() => TunnelAddress.DetectLan()?.Cidr;

    public bool Start(string roomCode, string secret, bool exposeLan, string rendezvous, out string message)
    {
        // 并发保护：重复点击或多个事件同时进来，只允许一个在起 / 停隧道
        lock (_gate) return StartLocked(roomCode, secret, exposeLan, rendezvous, out message);
    }

    private bool StartLocked(string roomCode, string secret, bool exposeLan, string rendezvous, out string message)
    {
        // 同房间同密钥同模式直接复用；换房间或换密钥必须重启，否则参数还是上一次的
        if (IsRunning && _room == roomCode && _secret == secret && _expose == exposeLan)
        {
            message = "EasyTier 已在运行";
            return true;
        }
        StopLocked();

        var core = ResolveCorePath();
        if (core == null) { message = "找不到 easytier-core.exe（可设 MEOW_EASYTIER 指向它）"; return false; }

        // 房间码 / 密钥 / 中继来自服务端或已验签配置，仍然严格校验，并用 ArgumentList 传参（不拼命令行字符串）
        if (!RoomShape.IsMatch(roomCode)) { message = "房间码格式不对"; return false; }
        if (secret.Length > 0 && !SecretShape.IsMatch(secret)) { message = "网络密钥格式不对"; return false; }
        if (!RelayShape.IsMatch(rendezvous)) { message = "中继地址格式不对"; return false; }

        KillStaleCore(core);

        var netName = "meow-" + roomCode;
        // 房间码只有 6 位，不能当网络密钥（猜一万次就中）。密钥由服务端随机下发，
        // 老服务端没有 secret 时才退回房间码，并在日志里明确警告。
        var netSecret = secret;
        if (netSecret.Length == 0)
        {
            netSecret = roomCode;
            Log?.Invoke("警告：服务端没下发随机密钥，正在用 6 位房间码当网络密钥");
        }

        var baseArgs = new List<string>
        {
            "--network-name", netName, "--network-secret", netSecret,
            "--dhcp", "--disable-upnp", "-p", rendezvous,
        };
        try
        {
            LogDir = Path.Combine(Path.GetTempPath(), "meow-easytier");
            Directory.CreateDirectory(LogDir);
            baseArgs.AddRange(new[] { "--file-log-dir", LogDir, "--file-log-level", "info" });
        }
        catch { }

        if (exposeLan)
        {
            var lan = TunnelAddress.DetectLan();
            if (lan == null)
            {
                message = "没找到可用的局域网网卡，地址暂时发布不了";
            }
            else
            {
                // 只代理跑游戏这一台机器（/32），不再把整个 /24 暴露给房间里的人。
                var last = lan.Address.GetAddressBytes()[3];
                var mapped = $"{TunnelAddress.MappedPrefix}.{last}/32";
                MappedPrefix = TunnelAddress.MappedPrefix;
                ProxiedAddress = lan.Address;
                ProxiedCidr = lan.Address + "/32";
                baseArgs.AddRange(new[] { "-n", $"{lan.Address}/32->{mapped}" });
                message = $"子网代理 {lan.Address}/32 → {mapped}";
            }
        }
        else
        {
            MappedPrefix = null;
            ProxiedAddress = null;
            ProxiedCidr = null;
            message = "加入端：不启用子网代理";
        }

        // 先试固定 RPC 端口 15888（easytier-cli 要连它才能看成员列表）；
        // 被残留实例占着时进程会立刻退出，再退回随机端口。两次都起不来就明确报失败，不再假装成功。
        var proc = TryLaunch(core, baseArgs, "127.0.0.1:15888", out var code1);
        if (proc is null)
        {
            Log?.Invoke($"15888 被占用或启动即退出（退出码 {code1}），改用随机 RPC 端口（成员列表不可用）");
            proc = TryLaunch(core, baseArgs, "0", out var code2);
            if (proc is null)
            {
                message = $"EasyTier 启动失败（退出码 {code2}）。可能缺少 wintun.dll、权限不足或被安全软件拦截。";
                return false;
            }
        }

        _proc = proc;
        ChildJob.Add(proc);   // RoomAgent 意外退出时，系统会连带结束 easytier-core，不留残留进程
        WritePid(proc.Id);
        _room = roomCode;
        _secret = secret;
        _expose = exposeLan;
        proc.Exited += (_, _) => Log?.Invoke("EasyTier 已退出");
        _ = PumpAsync(proc.StandardOutput);
        _ = PumpAsync(proc.StandardError);
        // 日志里不能带网络密钥
        Log?.Invoke("EasyTier 启动（已提权）：" + Redact(string.Join(' ', baseArgs), netSecret));
        return true;
    }

    /// <summary>起进程并观察 1.5 秒：还活着返回进程，已经退出返回 null（并给出退出码）。</summary>
    private static Process? TryLaunch(string core, List<string> baseArgs, string rpc, out int exitCode)
    {
        var psi = new ProcessStartInfo
        {
            FileName = core,
            WorkingDirectory = Path.GetDirectoryName(core)!,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var a in baseArgs) psi.ArgumentList.Add(a);
        psi.ArgumentList.Add("-r");
        psi.ArgumentList.Add(rpc);

        exitCode = -1;
        Process? p = null;
        try
        {
            p = Process.Start(psi);
            if (p is null) return null;
            p.EnableRaisingEvents = true;
            if (p.WaitForExit(1500))
            {
                exitCode = p.ExitCode;
                p.Dispose();
                return null;
            }
            return p;
        }
        catch
        {
            p?.Dispose();
            return null;
        }
    }

    private static string Redact(string text, string secret) =>
        secret.Length == 0 ? text : text.Replace(secret, "***", StringComparison.Ordinal);

    private static string PidFile => Path.Combine(Path.GetTempPath(), "meow-easytier", "core.pid");

    private static void WritePid(int pid)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PidFile)!);
            File.WriteAllText(PidFile, pid.ToString());
        }
        catch { }
    }

    /// <summary>上次崩溃留下的 easytier-core：pid 文件里的进程，且可执行路径就是我们这份 core，才结束它。</summary>
    private void KillStaleCore(string core)
    {
        try
        {
            if (!File.Exists(PidFile) || !int.TryParse(File.ReadAllText(PidFile).Trim(), out var pid)) return;
            using var old = Process.GetProcessById(pid);
            var path = old.MainModule?.FileName ?? "";
            if (string.Equals(Path.GetFullPath(path), Path.GetFullPath(core), StringComparison.OrdinalIgnoreCase))
            {
                old.Kill(entireProcessTree: true);
                old.WaitForExit(3000);
                Log?.Invoke("已清理上次残留的 EasyTier 进程");
            }
        }
        catch { /* 进程不存在或无权访问：忽略 */ }
        finally
        {
            try { File.Delete(PidFile); } catch { }
        }
    }

    private async Task PumpAsync(StreamReader reader)
    {
        try
        {
            string? line;
            while ((line = await reader.ReadLineAsync()) != null)
            {
                var text = line.Trim();
                if (text.Length == 0) continue;
                if (text.Contains(" INFO ", StringComparison.Ordinal)) continue;   // 心跳刷屏
                if (text.Contains("DEBUG", StringComparison.OrdinalIgnoreCase)) continue;
                if (!text.Contains("WARN", StringComparison.OrdinalIgnoreCase)
                    && !text.Contains("ERROR", StringComparison.OrdinalIgnoreCase)) continue;
                // 输出里偶尔会回显参数，密钥一律打码
                if (_secret.Length > 0) text = Redact(text, _secret);
                Log?.Invoke("EasyTier · " + (text.Length > 300 ? text[..300] + "…" : text));
            }
        }
        catch { }
    }

    public void Stop()
    {
        lock (_gate) StopLocked();
    }

    private void StopLocked()
    {
        try
        {
            if (_proc is { HasExited: false })
            {
                // 提权进程 Kill 会被拒，先试 taskkill
                using var tk = Process.Start(new ProcessStartInfo("taskkill.exe", $"/PID {_proc.Id} /T /F")
                { UseShellExecute = false, CreateNoWindow = true });
                tk?.WaitForExit(3000);
                if (!_proc.HasExited) _proc.Kill(entireProcessTree: true);
            }
        }
        catch { /* 仍可能拒绝，忽略 */ }
        _proc = null;
        try { File.Delete(PidFile); } catch { }
        _room = "";
        _secret = "";
        _expose = false;
        MappedPrefix = null;
        ProxiedAddress = null;
        ProxiedCidr = null;
    }

    public void Dispose() => Stop();
}

/// <summary>Job Object（退出即杀）：持有它的进程一结束，加入的子进程由系统一并结束。</summary>
internal static class ChildJob
{
    private static readonly IntPtr Job = Create();

    private static IntPtr Create()
    {
        try
        {
            var h = CreateJobObject(IntPtr.Zero, null);
            if (h == IntPtr.Zero) return IntPtr.Zero;
            var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.BasicLimitInformation.LimitFlags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            var len = Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
            var ptr = Marshal.AllocHGlobal(len);
            try
            {
                Marshal.StructureToPtr(info, ptr, false);
                if (!SetInformationJobObject(h, 9, ptr, (uint)len)) return IntPtr.Zero;
            }
            finally { Marshal.FreeHGlobal(ptr); }
            return h;
        }
        catch { return IntPtr.Zero; }
    }

    public static void Add(Process p)
    {
        try { if (Job != IntPtr.Zero) AssignProcessToJobObject(Job, p.Handle); } catch { }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateJobObject(IntPtr attrs, string? name);

    [DllImport("kernel32.dll")]
    private static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint len);

    [DllImport("kernel32.dll")]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }
}
