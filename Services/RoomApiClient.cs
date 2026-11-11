using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace MeowRoom.Services;

/// <summary>
/// 房间服务的 HTTP 客户端。服务地址来自云下发配置（RemoteConfig），代码里没有任何地址。
///
/// 行为：
/// - 按接口给超时：建房 / 加入 / 关房 / 离开 45 秒（服务端要走好几跳，而且不能自动重试），健康检查 10 秒，其余 20 秒。
/// - 只对「重试无副作用」的请求在失败后自动重试一次：GET、登录、中继准入。
///   建房 / 加入 / 关房这类可能已经在服务端生效的请求不自动重试，免得重复建房。
/// - 已登录状态下任何接口回 401（登录接口除外）→ 触发一次 SessionExpired，由宿主清登录态。
/// </summary>
public sealed class RoomApiClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly Func<string> _token;
    private int _expiredRaised;

    public event Action<string>? Log;

    /// <summary>登录票过期。宿主应清登录态并提示重新登录；重新登录成功后调用 <see cref="ResetSession"/>。</summary>
    public event Action? SessionExpired;

    /// <param name="tokenProvider">返回当前登录票；没登录返回空串。</param>
    /// <param name="http">可选：宿主自带的 HttpClient（比如要走指定线路）。其 Timeout 应设为无限，超时由本类按接口控制。</param>
    public RoomApiClient(Func<string> tokenProvider, HttpClient? http = null)
    {
        _token = tokenProvider;
        _http = http ?? new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
    }

    /// <summary>重新登录成功后调用，允许再次触发 SessionExpired。</summary>
    public void ResetSession() => Interlocked.Exchange(ref _expiredRaised, 0);

    public static TimeSpan TimeoutFor(string path) => path switch
    {
        "/api/health" => TimeSpan.FromSeconds(10),
        "/api/room/create" or "/api/room/join" or "/api/room/close" or "/api/room/leave" => TimeSpan.FromSeconds(45),
        _ => TimeSpan.FromSeconds(20),
    };

    public static bool IsRetryable(HttpMethod method, string path) =>
        method == HttpMethod.Get || path == "/api/login" || path == "/api/relay/open";

    /// <summary>发请求并把响应解析成 JSON。status 为 0 表示网络层失败（body 里有 error 文案）。</summary>
    public async Task<(int status, JsonElement body)> CallAsync(HttpMethod method, string path,
        object? payload = null, bool quiet = false, CancellationToken ct = default)
    {
        if (!await RemoteConfig.EnsureAsync(ct))
            return (0, JsonSerializer.SerializeToElement(new { error = RemoteConfig.LastError.Length > 0 ? RemoteConfig.LastError : "联机服务暂时不可用" }));

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var retryable = IsRetryable(method, path);
        HttpResponseMessage res;
        for (var attempt = 0; ; attempt++)
        {
            try { res = await SendOnceAsync(method, path, payload, ct); break; }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                if (!quiet) Log?.Invoke($"{method} {path} ✗ {sw.ElapsedMilliseconds}ms · {ex.Message}");
                if (retryable && attempt == 0)
                {
                    if (!quiet) Log?.Invoke("网络超时，自动重试一次");
                    continue;
                }
                return (0, JsonSerializer.SerializeToElement(new { error = "网络不通，检查网络或代理设置" }));
            }
        }

        using (res)
        {
            var code = (int)res.StatusCode;
            var text = await res.Content.ReadAsStringAsync(ct);
            if (!quiet || code >= 400) Log?.Invoke($"{method} {path} → {code} · {sw.ElapsedMilliseconds}ms");

            if (code == 401 && _token().Length > 0 && path != "/api/login"
                && Interlocked.Exchange(ref _expiredRaised, 1) == 0)
                SessionExpired?.Invoke();

            try
            {
                using var doc = JsonDocument.Parse(text);
                return (code, doc.RootElement.Clone());
            }
            catch
            {
                var snippet = text.Length > 120 ? text[..120] : text;
                return (code, JsonSerializer.SerializeToElement(new { error = $"HTTP {code}：{snippet}" }));
            }
        }
    }

    private async Task<HttpResponseMessage> SendOnceAsync(HttpMethod method, string path, object? payload, CancellationToken ct)
    {
        var baseUrl = RemoteConfig.Current?.RoomBase ?? throw new InvalidOperationException("没有服务配置");
        using var req = new HttpRequestMessage(method, baseUrl + path);
        var token = _token();
        if (token.Length > 0) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (payload is not null)
            req.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeoutFor(path));
        return await _http.SendAsync(req, cts.Token);
    }

    public void Dispose() => _http.Dispose();
}
