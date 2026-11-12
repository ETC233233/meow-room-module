# 第三方组件

本仓库**只含模块自己的源码**（MIT，见 `LICENSE`），**不包含、也不分发**下列任何组件的二进制。宿主应用如果把它们打进自己的发布包，就由宿主负责遵守各自的许可证——最少要随包附上许可证全文、版权声明和源码获取方式。

## 运行时依赖（需自行获取，原样使用，不要修改文件）

| 组件 | 许可证 | 用法 | 上游 |
|---|---|---|---|
| EasyTier | LGPL-3.0 | 通过命令行启动独立进程 `easytier-core.exe`，没有链接它的代码 | https://github.com/EasyTier/EasyTier |
| WinDivert（`Packet.dll`、`WinDivert64.sys`，随 EasyTier 发布包） | LGPL-3.0 或 GPL-2.0（双许可） | 由 EasyTier 加载，本模块不直接调用 | https://github.com/basil00/WinDivert |
| Wintun（`wintun.dll`，随 EasyTier 发布包） | WireGuard LLC「Prebuilt Binaries License」（预编译二进制许可证） | 由 EasyTier 加载，本模块不直接调用 | https://www.wintun.net/ |

宿主分发这些二进制时要注意：

- **LGPL（EasyTier、WinDivert）**：随包附 LGPL-3.0 与 GPL-3.0 全文、保留版权声明、写明对应源码的获取地址；文件不能被改动；用户应能替换为自己编译的版本。
- **Wintun**：只能随「仅通过其公开 API 使用它」的软件（这里是 EasyTier）一起分发；不得单独分发、修改、反编译，不得用 WireGuard / Wintun 的名义为产品背书；必须保留其许可证文本。
- 以上以各上游仓库 / 官网附带的许可证原文为准；本文只是便于宿主核对的摘要，不构成法律意见。
- 参考做法：MeowLauncher 的发布包带有 `Licenses\`（各许可证全文）和 `THIRD-PARTY-NOTICES.md`。

## NuGet 依赖

| 包 | 许可证 | 用途 |
|---|---|---|
| BouncyCastle.Cryptography 2.4.0 | MIT | 云配置的 Ed25519 验签 |
| System.IO.Pipes.AccessControl 5.0.0（仅 `RoomAgent`） | MIT | 管道权限 |

## 商标

本模块与 Mojang、Microsoft、Minecraft、Cloudflare、EasyTier、WireGuard 均无隶属关系；相关名称归各自所有者。
