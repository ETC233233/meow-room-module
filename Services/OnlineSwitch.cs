namespace MeowRoom.Services;

/// <summary>
/// 联机功能总开关，<b>默认关闭</b>。宿主（启动器）在用户启用联机功能后显式打开：
/// <code>OnlineSwitch.Enabled = true;</code>
/// 关着的时候：配置不会去拉取、房间服务不会被调用、提权代理不会被拉起、实时通道不会连接——
/// 模块对外不产生任何网络请求，也不会弹 UAC。第一版发布不带联机功能，就靠这个开关保证。
/// </summary>
public static class OnlineSwitch
{
    public const string DisabledMessage = "联机功能未启用";

    /// <summary>默认 false。提权代理进程只会被已启用联机的宿主拉起，所以代理启动时会把它设为 true。</summary>
    public static bool Enabled { get; set; }
}
