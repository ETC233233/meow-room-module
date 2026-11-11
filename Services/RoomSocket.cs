using System.Net.WebSockets;
using System.Text;
using System.Text.Json;

namespace MeowRoom.Services;

/// <summary>
/// 房间实时通道（WebSocket）：服务端主动推房间状态，断线自动重连。
///
/// - 心跳：每 30 秒发 "ping"，10 秒内没收到任何消息就判定通道已死，断开重连。
/// - 重连：指数退避，1 秒起、最多 10 秒。
/// - 连接被 401 拒绝：登录票过期，重连没有意义，触发 Unauthorized 后结束。
/// - 收到 closed：房间已关闭，触发 Closed 后结束。
/// </summary>
public sealed class RoomSocket
{
    public const int HeartbeatSeconds = 30;
    public const int PongTimeoutSeconds = 10;

    private readonly Func<string> _token;

    public event Action<string>? Log;

    /// <summary>服务端推来的房间状态（room 对象）。</summary>
    public event Action<JsonElement>? State;

    public event Action? Closed;
    public event Action? Unauthorized;

    public RoomSocket(Func<string> tokenProvider) => _token = tokenProvider;

    /// <summary>跑到房间关闭、登录过期或被取消为止。</summary>
    public async Task RunAsync(string roomCode, CancellationToken ct)
    {
        var wait = 1000;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var cfg = RemoteConfig.Current;
                if (cfg is null) throw new InvalidOperationException("没有服务配置");
                var baseWs = cfg.RoomBase.Replace("https://", "wss://").Replace("http://", "ws://");

                using var ws = new ClientWebSocket();
                ws.Options.SetRequestHeader("Authorization", "Bearer " + _token());
                await ws.ConnectAsync(new Uri($"{baseWs}/api/room/ws?code={Uri.EscapeDataString(roomCode)}"), ct);
                wait = 1000;
                Log?.Invoke("实时通道已连接");

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

                        using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(ms.ToArray()));
                        var root = doc.RootElement.Clone();
                        var type = root.TryGetProperty("type", out var t) ? t.GetString() : "";
                        if (type == "pong") continue;
                        if (type == "closed") { Closed?.Invoke(); return; }
                        if (type == "state" && root.TryGetProperty("room", out var room)) State?.Invoke(room);
                    }
                }
                finally { hb.Cancel(); }
            }
            catch (Exception ex)
            {
                if (ct.IsCancellationRequested) return;
                if (ex is WebSocketException && ex.Message.Contains("401", StringComparison.Ordinal))
                {
                    Unauthorized?.Invoke();
                    return;
                }
                Log?.Invoke("实时通道断开：" + ex.Message + "，重连中");
            }

            try { await Task.Delay(wait, ct); } catch { return; }
            wait = Math.Min(wait * 2, 10_000);
        }
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
                    Log?.Invoke("实时通道心跳超时，重连");
                    ws.Abort();
                    return;
                }
            }
        }
        catch { /* 取消或连接已断：由 RunAsync 处理 */ }
    }
}
