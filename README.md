# DSH Remote

从 Tiana 托管网页安全访问本机 DeepSeek Harness（DSH）。通过 Tiana Function Relay 完成端到端加密认证（ECDH P-256 + HKDF-SHA256 + AES-256-GCM），支持 WebRTC P2P 直连与 Relay 加密中继无感切换，并提供原生子资源流式桥接、大媒体 `206 Partial Content` 窗口流控、主线程 `EventSource`（SSE）保活、DSH 侧栏配置面板与云端一键引导绑定。

## 一键绑定与安装（推荐）

前置要求：`Node.js >= 24.9.0`（与 `@deepseek-ai/dsh` 对齐）。

在 Tiana 应用市场安装 **DSH Remote** 应用并打开后，页面向导会提供针对当前系统的绑定命令：

```sh
npx --yes @tianacloud/dsh-remote@latest connect --app <appId>
```

`connect` 会自动完成：
1. 校验本机 `Node.js >= 24.9.0`（低于版本友好提示 `fnm`/`nvm`/`winget` 升级命令并安全退出）；
2. 检测已有 `dsh`（未装时自动安装 `@deepseek-ai/dsh@latest`，无全局写权限回退 `~/.local`，绝不调用 `sudo`），幂等启用 `@tianacloud/dsh-tiana` 与 `@tianacloud/dsh-remote`（完整保留既有项目、对话与其他插件）；
3. 核验 `tiana` 登录态与应用所有者权限，通过 `DSH_REMOTE_POLICY` 参数免重编译完成云端策略绑定（耗时 `< 3s`）；
4. 启动或热通知本机 DSH，经系统剪贴板管道复制 `dshk1_...` 配对密钥（**绝不将密钥拼入 URL hash 或 query**），打开干净的远程访问地址，网页向导收到 `host_online` 广播后毫秒级自动切入解锁页。

本机先行首次创建云端资源仍支持 `dsh-remote setup`。

## 侧栏管理面板与安全边界

- **本地 DSH 侧栏（Tiana Remote）**：可视化查看在线状态与延迟、热开关远程访问、打开／复制／扫码访问远程 URL、默认掩码查看／复制／二次确认轮换 E2EE 配对密钥（轮换立即以 `4001 key_rotated` 断开所有远端会话）、管理活跃会话与单会话踢出、热更新 P2P／STUN／前端放行插件白名单，以及一键修复重推静态壳层。
- **远端隧道受限视图**：在托管网页中打开同一侧栏时自动切换为安全受限模式，展示当前通道（`P2P`／`Relay`）与 RTT，提供「刷新前端模块缓存」与「锁定并清除此设备密钥」，**不展示任何配对密钥或宿主管理操作**。
- **双重管理路由隔离**：`HostBridge` 对经远端隧道发往 `/api/tiana-remote/admin` 及子路径的请求直接拦截返回 `403 Forbidden`，并在所有转发请求强制注入 `X-DSH-Remote-Tunnel: 1`；本机 `src/remote-api.js` 额外实施回环地址 + 非隧道头 + 本机 DSH `owner` 会话三重守卫。
- **配对密钥存储策略**：解锁页默认勾选「在此受信任浏览器记住密钥」（勾选时保存在当前浏览器 `localStorage`，下次打开免输直连；取消勾选时密钥仅驻留当前标签页 JS 内存，绝不写入 `localStorage` 或 `sessionStorage`，刷新或关闭标签页即销毁；点击锁定通过跨标签页广播立即清空内存与本地存储）。

## 远端浏览器子资源、流式媒体与 SSE 桥接

- **无密钥流式 Service Worker（`dsh-remote-sw.js`）**：零密钥、零 `CacheStorage` 持久化，支持原生 `<img>`（含客户端 `3xx` 跟随）、`<video>`／`<audio>` `Range`/`206 Partial Content`、流式 `<a download>` 与沙箱 `<iframe>`；所有合成响应强制附加 `X-Content-Type-Options: nosniff`、`Cache-Control: no-store`，并对 `image/svg+xml`、`text/html`、`application/xhtml+xml` 强制施加不含 `allow-same-origin` 的 `Content-Security-Policy: sandbox` 防 XSS。
- **官方文件上传闭合**：入口挂载 `globalThis.__DSH_FILE_UPLOAD__ = { fetch: globalThis.fetch }`，使 `@deepseek-ai/dsh-client-file-upload` 直接走主线程加密隧道上传并保留 `AbortSignal` 即时取消。
- **窗口流控与并发隔离**：单会话最大并发流 `MAX_STREAMS = 64`，SW 子资源只读请求独立并发队列（上限 `16`）；双端通过内层加密帧 `MSG_HTTP_RES_WINDOW (0x17)` 执行 `4 MiB` 接收窗口信用流控，大体积媒体暂停或拖动进度条内存占用有界且与旧版对端双向兼容。
- **主线程 `EventSource`（SSE）与滑动活性保活**：主线程提供标准 W3C `EventSource` 桥接（具名事件、`Last-Event-ID` 重连、`retry:`、`close()` 即时 `MSG_HTTP_ABORT`）；`HostBridge` 采用流活动滑动 `5 分钟` 超时、对 `text/event-stream` 上游强制设置 `Accept-Encoding: identity`，并在上游静默每 `25s` 自动注入 `: keepalive\n` 心跳。
- **无 SW 受限容器极简防御（方案 A）**：SW 注册限时 `1500 ms` 绝不阻塞启动；无 SW 环境下主线程上传、`fetch`（含 `3xx` 跟随）、`EventSource` 与 `/api/remote.mux` WebSocket 100% 可用，仅在工作台顶部展示可手动关闭的系统浏览器打开提示条。

## 本地验证

```sh
(cd relay-go && go test -race ./... && go vet ./...)
npm test
npm run build:web
npm run test:pack
```
