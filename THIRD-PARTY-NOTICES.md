# 第三方组件

本仓库**只含模块自己的源码**，不包含、也不分发下列任何组件的二进制。使用方需自行从上游获取，并以上游随版本附带的 LICENSE 为准。

## 运行时依赖（需自行获取）

- **EasyTier**：https://github.com/EasyTier/EasyTier
  模块通过命令行调用 `easytier-core.exe`。请从官方发布页下载，原样放置，不要修改文件（驱动签名）。
- **WinDivert**（随 EasyTier 发布包带的 `Packet.dll`、`WinDivert64.sys`）：https://github.com/basil00/WinDivert
- **Wintun**（`wintun.dll`）：https://www.wintun.net/

各组件的许可证请到上游仓库核对；本仓库不转述、也不对其许可证条款作任何说明。

## NuGet 依赖

- **BouncyCastle.Cryptography**：用于 Ed25519 验签。许可证见该 NuGet 包。
- **System.IO.Pipes.AccessControl**（仅 `RoomAgent`）。
