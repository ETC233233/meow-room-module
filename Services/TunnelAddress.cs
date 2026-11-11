using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace MeowRoom.Services;

/// <summary>
/// 隧道地址的唯一实现。启动器和提权模块都链接这个文件，
/// 避免两边各挑一块网卡、各算一个地址。
/// 规则：只认走默认网关的那块局域网网卡，把它映射到 172.16.99.&lt;末段&gt;。
/// </summary>
public static class TunnelAddress
{
    public const string MappedPrefix = "172.16.99";

    public sealed record Lan(string Cidr, IPAddress Address, int PrefixLength);

    /// <summary>找真正的局域网网卡；优先有默认网关的那块。</summary>
    public static Lan? DetectLan()
    {
        Lan? fallback = null;
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;

            var tag = (nic.Name + " " + nic.Description).ToLowerInvariant();
            if (IsVirtual(tag)) continue;

            var props = nic.GetIPProperties();
            var hasGateway = props.GatewayAddresses.Any(g =>
                g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any));

            foreach (var ua in props.UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                if (IsExcluded(ua.Address)) continue;

                var mask = ua.IPv4Mask.GetAddressBytes();
                if (mask.Length != 4) continue;
                var bits = 0;
                foreach (var b in mask) bits += System.Numerics.BitOperations.PopCount(b);
                if (bits is 0 or 32) continue;

                var ip = ua.Address.GetAddressBytes();
                var net = new byte[4];
                for (var i = 0; i < 4; i++) net[i] = (byte)(ip[i] & mask[i]);
                var lan = new Lan($"{net[0]}.{net[1]}.{net[2]}.{net[3]}/{bits}", ua.Address, bits);
                if (hasGateway) return lan;
                fallback ??= lan;
            }
        }
        return fallback;
    }

    public static bool IsExcluded(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        if (b.Length != 4) return true;
        if (b[0] is 0 or 127) return true;
        if (b[0] == 169 && b[1] == 254) return true;                   // APIPA
        if (b[0] == 10 && (b[1] == 126 || b[1] == 144)) return true;   // EasyTier DHCP 自己的网段
        if (b[0] == 172 && b[1] == 16 && b[2] == 99) return true;      // 映射网段本身
        return false;
    }

    private static bool IsVirtual(string tag) =>
        tag.Contains("easytier") || tag.Contains("wintun") || tag.Contains("tailscale") ||
        tag.Contains("zerotier") || tag.Contains("vethernet") || tag.Contains("hyper-v") ||
        tag.Contains("vmware") || tag.Contains("virtualbox") || tag.Contains("docker") ||
        tag.Contains("wsl") || tag.Contains("bluetooth") || tag.Contains("tap-") || tag.Contains("tun");

    /// <summary>用一条确定的局域网 IP 生成隧道地址；端口或网卡不合法就返回 null。</summary>
    public static string? Build(int port, IPAddress? lanAddress, string? mappedPrefix = null)
    {
        if (port is < 1024 or > 65535) return null;
        if (lanAddress is null) return null;
        var b = lanAddress.GetAddressBytes();
        if (b.Length != 4 || IsExcluded(lanAddress)) return null;
        return $"{mappedPrefix ?? MappedPrefix}.{b[3]}:{port}";
    }
}
