namespace MeowRoom.Services;

/// <summary>
/// 提权代理的落盘位置。管理员进程不能往用户可写的目录（%TEMP%、用户目录）里写东西或从里面执行文件：
/// 那些位置同用户的任何程序都能预先放好符号链接 / 联接点，让提权进程去覆盖别的文件。
/// 所以日志、pid 文件、EasyTier 组件都放在 %ProgramFiles%（普通用户没有写权限）下。
/// </summary>
public static class AgentPaths
{
    /// <summary>仅供自测使用：把根目录换成临时目录（自测不是管理员，写不了 Program Files）。</summary>
    public static string? Override { get; set; }

    public static string Root => Override
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "MeowLauncher");

    /// <summary>运行期文件（日志、pid）。目录不存在会创建；没有权限创建时抛异常，由调用方吞掉。</summary>
    public static string RunDir
    {
        get
        {
            var d = Path.Combine(Root, "run");
            Directory.CreateDirectory(d);
            return d;
        }
    }

    /// <summary>EasyTier 组件校验后的落点：components\easytier\&lt;清单指纹&gt;\</summary>
    public static string ComponentsDir => Path.Combine(Root, "components", "easytier");
}
