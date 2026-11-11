using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace MeowRoom.Services;

/// <summary>
/// 直接问系统「哪个 java 进程在监听」。
/// 不能解析 netstat 文本：某些监听 socket 状态字段是 0，netstat 会整行不打印
/// （实测 Minecraft 双栈 LAN 端口就是，连得上但 netstat 列表里没有）。
/// 所以走 GetExtendedTcpTable，凡是「远端端口为 0」的行都算监听，不依赖状态字段。
/// </summary>
public static class McPortScanner
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder,
        int ulAf, int tableClass, uint reserved);

    private sealed record Listener(int Pid, int Port, bool Wildcard);

    /// <summary>返回 java/javaw 进程正在监听的端口；找不到返回 null。</summary>
    public static int? FindLanPort()
    {
        var javaPids = JavaPids();
        if (javaPids.Count == 0) return null;
        var ports = Listeners()
            .Where(l => javaPids.Contains(l.Pid))
            .ToList();
        if (ports.Count == 0) return null;

        var wildcard = ports.Where(l => l.Wildcard).Select(l => l.Port).ToList();
        var pool = wildcard.Count > 0 ? wildcard : ports.Select(l => l.Port).ToList();
        return pool.Max();
    }

    /// <summary>这个端口当前是否真的在监听（不区分进程）。</summary>
    public static bool IsListening(int port)
    {
        if (port is < 1 or > 65535) return false;
        var all = Listeners();
        if (all.Count > 0) return all.Any(l => l.Port == port);
        return CanConnect(port);
    }

    /// <summary>列出「java 进程 → 它监听的最大端口」，给房主挑选要开放的实例。</summary>
    public static Dictionary<int, int> ListenPorts()
    {
        var javaPids = JavaPids();
        var listeners = Listeners();
        // 按进程名没找到时，再按监听行的 PID 反查一次进程（有些启动方式下按名字枚举会漏）
        foreach (var pid in listeners.Select(l => l.Pid).Distinct())
            if (!javaPids.Contains(pid) && LooksJava(pid)) javaPids.Add(pid);

        var result = new Dictionary<int, int>();
        foreach (var l in listeners)
        {
            if (!javaPids.Contains(l.Pid)) continue;
            if (!result.TryGetValue(l.Pid, out var old) || l.Port > old) result[l.Pid] = l.Port;
        }
        return result;
    }

    /// <summary>诊断用：监听总数、识别到的 java 进程数、通配监听样例。</summary>
    public static string Diagnose()
    {
        var listeners = Listeners();
        var pids = JavaPids();
        foreach (var pid in listeners.Select(l => l.Pid).Distinct())
            if (!pids.Contains(pid) && LooksJava(pid)) pids.Add(pid);

        var sample = listeners.Where(l => l.Wildcard).Select(l => l.Pid).Distinct().Take(6)
            .Select(pid => $"{pid}:{NameOf(pid)}");
        return $"监听 {listeners.Count} 条，java 进程 {pids.Count} 个，通配 PID 样例 {string.Join(",", sample)}";
    }

    /// <summary>java 识别不出来时的兜底：所有用户态通配监听里最大的几个端口。</summary>
    public static Dictionary<int, int> WildcardPorts()
    {
        var result = new Dictionary<int, int>();
        foreach (var l in Listeners())
        {
            if (!l.Wildcard || l.Pid <= 4) continue;
            if (l.Port is < 1024 or > 65535) continue;
            if (!result.TryGetValue(l.Pid, out var old) || l.Port > old) result[l.Pid] = l.Port;
        }
        return result;
    }

    private static string NameOf(int pid)
    {
        try { return Process.GetProcessById(pid).ProcessName; } catch { return ""; }
    }

    private static bool LooksJava(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            var name = p.ProcessName.ToLowerInvariant();
            if (name.StartsWith("java")) return true;
            // 任务管理器里游戏常挂在 Zulu/JDK 分组下，进程名不一定是 java；窗口标题更可靠
            var title = p.MainWindowTitle;
            if (title.Contains("Minecraft", StringComparison.OrdinalIgnoreCase)) return true;
            var path = p.MainModule?.FileName?.ToLowerInvariant() ?? "";
            return path.Contains("\\java") || path.Contains("\\jdk") || path.Contains("zulu");
        }
        catch { return false; }
    }

    private static HashSet<int> JavaPids()
    {
        var pids = new HashSet<int>();
        foreach (var name in new[] { "javaw", "java" })
        {
            try
            {
                foreach (var p in Process.GetProcessesByName(name)) pids.Add(p.Id);
            }
            catch { }
        }
        return pids;
    }

    private static List<Listener> Listeners()
    {
        var list = new List<Listener>();
        ReadTable(AF_INET, 24, list);
        ReadTable(AF_INET6, 56, list);
        return list;
    }

    private static void ReadTable(int af, int rowSize, List<Listener> sink)
    {
        var size = 0;
        var rc = GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc != ERROR_INSUFFICIENT_BUFFER || size <= 0) return;

        var buf = Marshal.AllocHGlobal(size);
        try
        {
            rc = GetExtendedTcpTable(buf, ref size, false, af, TCP_TABLE_OWNER_PID_ALL, 0);
            if (rc != 0) return;

            var count = Marshal.ReadInt32(buf);
            var row = IntPtr.Add(buf, 4);
            for (var i = 0; i < count; i++, row = IntPtr.Add(row, rowSize))
            {
                int localPort, remotePort, pid;
                bool wildcard;
                if (af == AF_INET)
                {
                    var local = (uint)Marshal.ReadInt32(row, 4);
                    localPort = PortOf((uint)Marshal.ReadInt32(row, 8));
                    remotePort = PortOf((uint)Marshal.ReadInt32(row, 16));
                    pid = Marshal.ReadInt32(row, 20);
                    wildcard = local == 0;
                }
                else
                {
                    wildcard = true;
                    for (var b = 0; b < 16; b++)
                        if (Marshal.ReadByte(row, b) != 0) { wildcard = false; break; }
                    localPort = PortOf((uint)Marshal.ReadInt32(row, 20));
                    remotePort = PortOf((uint)Marshal.ReadInt32(row, 44));
                    pid = Marshal.ReadInt32(row, 52);
                }

                // 远端端口为 0 就是一条监听记录；不再依赖 dwState（有的监听 socket 状态是 0）
                if (remotePort != 0) continue;
                if (localPort is < 1024 or > 65535) continue;
                sink.Add(new Listener(pid, localPort, wildcard));
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static int PortOf(uint raw) =>
        (ushort)IPAddress.NetworkToHostOrder((short)(raw & 0xFFFF));

    private static bool CanConnect(int port)
    {
        foreach (var addr in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
        {
            try
            {
                using var c = new TcpClient(addr.AddressFamily);
                var task = c.ConnectAsync(addr, port);
                if (task.Wait(400) && c.Connected) return true;
            }
            catch { }
        }
        return false;
    }
}
