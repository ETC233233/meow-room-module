# meow-room-module

MeowLauncher 的联机模块源码（Windows）。**这是模块源码，不含启动器，不含服务端。**

它负责：从云端拿到已签名的服务配置、和房间服务通信、在提权的 `RoomAgent` 里起 EasyTier 隧道、扫描局域网游戏端口、发布房主地址。启动器（宿主程序）通过引用本模块来使用它。

## 里面有什么

| 路径 | 作用 |
|---|---|
| `Services/RemoteConfig.cs` | 云下发配置：在线拉取 → 验 Ed25519 签名 → 解析；只放内存 |
| `Services/RoomApiClient.cs` | 房间服务 HTTP 客户端：分接口超时、安全请求自动重试、401 通知 |
| `Services/RoomSocket.cs` | 房间实时通道（WebSocket）：30 秒心跳、断线重连 |
| `Services/AgentClient.cs` | 宿主这一侧：提权拉起 `RoomAgent`，带一次性 token 握手 |
| `Services/EasyTierService.cs` | 起 / 停 EasyTier：参数校验、密钥打码、退出清理 |
| `Services/TunnelAddress.cs`、`LanHost.cs`、`McPortScanner.cs`、`GameInfo.cs`、`EdgeLocator.cs` | 地址映射、局域网识别、游戏端口扫描、实例信息、Cloudflare 边缘测速 |
| `RoomAgent/` | 提权代理：单独的管理员进程，只在建隧道时需要 |
| `tools/sign-config.mjs` | 给配置签名的小工具（私钥只从环境变量读） |
| `MeowRoom.Module.csproj` | 模块库工程 |

## 里面没有什么

- **没有启动器界面**，也没有演示窗口。
- **没有服务端**：房间服务、中继闸门、验证服务都不在这里。
- **没有 EasyTier 二进制**：需要自行从官方发布页下载并放到宿主的 `easytier\` 目录，文件不得改动。见 `THIRD-PARTY-NOTICES.md`。
- **没有任何服务器地址**：源码里没有 IP、域名、中继地址，连占位默认值也没有。

## 云下发配置

房间服务地址、中继、边缘 IP 都不写在代码里，由配置入口在线下发，以后地址变了客户端不用发版。

1. 入口地址和验签公钥**不在源码里**，构建时注入：
   ```powershell
   dotnet build MeowRoom.Module.csproj -c Release -p:Platform=x64 `
     -p:MeowConfigEntry=https://<你的配置入口> -p:MeowConfigKeys=k1:<Ed25519公钥base64>
   ```
   宿主引用本模块时，在宿主的构建命令里传同样的属性即可（会一路传到模块）。公钥可以放两把，逗号分隔，用于轮换。
2. 入口返回信封 `{"payload":"<JSON 文本>","sig":"<base64>","kid":"k1"}`。客户端**先验 Ed25519 签名，再解析 payload**。
   payload 字段：`version`(=1)、`issuedAt`、`expiresAt`(unix 秒，容忍 ±5 分钟)、`roomBase`(https)、`relay`(`tcp://host:port`)、`edgeIps`(可选)、`cfRoute`(可选)。
3. 验签失败、过期、版本未知、格式不对一律视为不可用：返回失败，**不会退回旧地址**。配置只放内存，不落盘、不写日志。
4. `RoomAgent`（管理员权限）自己没有地址，只接受宿主验签后传来的值。

签名：`tools/sign-config.mjs keygen` 生成密钥对，`sign` 对配置签名。私钥应只放在你自己的配置服务（例如 Worker secret）里，不要进仓库。

Debug 构建支持 `MEOW_DEV_CONFIG=<本地 json 文件>` 跳过网络和验签做本地联调；发布版没有这条路。

## 宿主怎么用

```csharp
using MeowRoom.Services;

// 1. 配置（失败就提示"联机服务暂时不可用"，不要退回旧地址）
if (!await RemoteConfig.EnsureAsync()) { /* RemoteConfig.LastError */ return; }

// 2. 调房间服务；tokenProvider 返回当前登录票
var api = new RoomApiClient(() => myToken);
api.SessionExpired += () => { /* 清登录态，提示重新登录；重新登录后 api.ResetSession() */ };
var (status, body) = await api.CallAsync(HttpMethod.Post, "/api/login", new { type = "offline", name });

// 3. 房间实时状态
var socket = new RoomSocket(() => myToken);
socket.State += room => { /* 刷新界面 */ };
socket.Closed += () => { /* 房间已关闭 */ };
_ = socket.RunAsync(roomCode, cts.Token);

// 4. 起隧道（会弹一次 UAC；relay 和 roomBase 从 RemoteConfig.Current 里取）
var cfg = RemoteConfig.Current!;
var agent = new AgentClient();
await agent.StartAsync(roomCode, secret, expose: true, api: cfg.RoomBase, token: myToken, rendezvous: cfg.Relay, port: gamePort);
```

`RoomAgent.exe` 要放在宿主 exe 同级目录（或用环境变量 `MEOW_AGENT` 指定）。

## 构建

```powershell
dotnet build RoomAgent\RoomAgent.csproj -c Release -p:Platform=x64
```

需要 .NET 8 SDK，仅限 Windows（x64）。

## 已知限制

下面这些**没有经过真实环境验证**，使用前请自行测：

- **`RoomSocket` 没有对真实的 WebSocket 服务测过**：只做了编译。心跳超时重连、断线退避重连、被 401 拒绝后停止重连、收到 `closed` 结束，这几条路径都没有实测。
- **提权起隧道的完整流程没有在真机上走通**：`AgentClient` → UAC → `RoomAgent` → EasyTier。`RoomAgent` 控制口的 token 握手单独测过（错误 token、不发 hello 都被直接断开，正确 token 收到就绪消息和 pong），但经 UAC 拉起的整条链路没有完整跑过。
- **`EasyTierService` 没有真起过隧道**：参数校验、密钥打码、两次启动检测、Job Object 清理都只验证了能编译，没有对着真实的 `easytier-core` 运行测试。
- **`RoomApiClient` 只对本地假服务测过**（登录断线自动重试、建房断线不重试、401 只触发一次等），没有在真实服务上长时间跑过。
- 服务端的登录目前是模拟校验，公开部署前需要接真实的微软校验（服务端，不在本仓库）。

## 行为约定

- 建房 / 加入 / 关房 / 离开超时 45 秒且**不自动重试**（可能已在服务端生效，重试会重复建房）；GET、登录、中继准入超时后自动重试一次。
- 已登录状态下接口返回 401 → 触发一次 `SessionExpired`。
- 实时通道每 30 秒心跳，10 秒没回应就重连；连接被 401 拒绝则不再重连。
- 控制口 `127.0.0.1:47831` 要求一次性 token 握手，见 `SECURITY.md`。

## 许可证

MIT，见 `LICENSE`。第三方组件见 `THIRD-PARTY-NOTICES.md`。
