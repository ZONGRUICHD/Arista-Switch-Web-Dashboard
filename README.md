# Arista 7050 Switch Dashboard

面向 Arista DCS-7050QX-32S-F 的轻量级 on-box 运维界面。生产服务由 EOS 上的 Python 3.9 标准库直接运行，不依赖容器、Node.js 或外部 CDN；浏览器端使用原生 HTML、CSS 和 JavaScript。

默认生产地址为 `https://192.168.0.248:2480/`。服务只接受 HTTPS，所有状态接口均需登录，配置操作还需临时解锁。

## 安全模型

- Dashboard 账号可与 EOS 账号保持一致，但磁盘上只保存带随机盐的 PBKDF2 密码摘要，不保存明文密码。
- 登录 Cookie 使用 `Secure`、`HttpOnly` 和 `SameSite=Strict`；写请求同时校验 CSRF token。
- 普通登录会话最长 12 小时。配置操作必须再次输入密码解锁，解锁状态 15 分钟后自动失效。
- 不提供任意 CLI 文本执行。诊断接口只接受固定命令 ID 和经过严格校验的参数。
- 配置变更先生成预览和差异；提交时先取得 EOS transaction configuration lock，再复核完整 running-config 基线，并通过 configuration session 提交。任一步骤失败时拒绝提交并 abort，结果不确定时禁止自动重放。
- CLI 执行受并发、超时和聚合输出硬上限约束；运行配置超过安全基线上限时失败关闭，不会对截断前缀计算哈希。
- TLS 私钥、认证配置、运行元数据和日志目录必须能设置 POSIX 权限；无法设置 `0600`/`0700` 时安装器会安全退出。
- 本项目不会为管理网络开启外部 eAPI。状态读取继续优先使用本机 eAPI/Unix socket，并按需回退本机 `Cli`/`FastCli`。

## 项目结构与开发

- `web/`：唯一的前端源码，包括页面、样式和浏览器逻辑。
- `tools/build_onbox.py`：确定性地把 `web/` 嵌入生产文件，并可检查生成物是否漂移。
- `onbox/arista7050_web.py`：生成后的单文件 EOS 部署产物，同时包含后端和前端。
- `server.js`：仅监听 `127.0.0.1` 的本地 fixture 预览服务器；不连接交换机、不接收 SSH 凭据。
- `install.sh`：固定版本、校验摘要、候选验证、原子替换及自动回滚安装器。

生成 on-box 文件：

```bash
python3 tools/build_onbox.py
```

检查 Git 中的生成物与 `web/` 是否一致：

```bash
python3 tools/build_onbox.py --check
```

启动本地 fixture 预览：

```bash
npm ci
npm start
```

预览服务仅在 `http://127.0.0.1:3000/` 可用。它使用 `data/fixtures/state.json` 等 fixture 数据，不应承载真实交换机密码，也不能作为生产服务。

运行基础验证：

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile onbox/arista7050_web.py
node --check server.js
node --check web/app.js
npm run test:e2e
```

## 安全部署

### 1. 准备固定版本

生产安装只接受完整的 40 位十六进制 Git commit，不接受分支、标签、短 SHA、`master`、`main` 或 `HEAD`。先确定已审核的 commit，并计算该 commit 中 on-box 文件的 SHA-256：

```bash
REF=<40-character-reviewed-commit>
git show "$REF:onbox/arista7050_web.py" | sha256sum
```

注意：Git 会按仓库内容输出文件；请使用该命令得到的 64 位摘要，不要使用工作区中可能含 CRLF 转换的副本计算生产摘要。

### 2. 在交换机上运行安装器

进入 EOS 的 `enable` 和 `bash`，再下载同一固定 commit 中的安装器：

```text
enable
bash
```

```sh
REF=<40-character-reviewed-commit>
ARTIFACT_SHA=<64-character-sha256>
curl -fL "https://raw.githubusercontent.com/ZONGRUICHD/Arista-Switch-Web-Dashboard/$REF/install.sh" \
  -o /tmp/arista-dashboard-install.sh
sudo -n env REF="$REF" ARTIFACT_SHA="$ARTIFACT_SHA" \
  sh /tmp/arista-dashboard-install.sh
```

EOS 的 `/mnt/flash` 和 on-boot 进程由 root 管理，因此安装器会在任何文件变更前检查有效 UID；普通 `admin` Bash 会安全退出，需使用上面的无交互 `sudo -n env` 形式。

若交换机管理 VRF 无法解析或访问 GitHub，可先通过受信任的 SSH/SCP 通道把同一 commit 的 `onbox/arista7050_web.py` 传到临时路径，再使用离线源；安装器仍会在任何切换前校验 `ARTIFACT_SHA`：

```sh
sudo -n env REF="$REF" ARTIFACT_SHA="$ARTIFACT_SHA" \
APP_SOURCE=/tmp/arista7050-web-reviewed.py \
  sh /tmp/arista-dashboard-install.sh
```

`APP_SOURCE` 和 `APP_URL` 互斥。离线文件必须是普通可读文件，且其 SHA-256 必须与已审核 commit 的 Git 对象一致。

首次安装会从 `/dev/tty` 提示输入 EOS/Dashboard 密码。密码不会作为命令行参数、环境变量或日志内容出现。安装器默认执行以下流程：

1. 检查 Python、OpenSSL、下载工具、写权限和至少 8 MiB 可用空间。
2. 下载固定 commit 的产物并验证显式 SHA-256，随后进行 Python 编译检查。
3. 在 EOS 的安全持久目录 `/persist/secure/arista-dashboard/` 生成权限为 `0600` 的认证配置和自签名 RSA 证书。证书 SAN 默认包含 `192.168.0.248` 和 `Arista7050`。应用产物与有限备份仍位于 flash，避免把私钥放到不支持 POSIX 权限的 VFAT 文件系统。
4. 通过原子安装锁阻止并发安装，清理经过 PID 和 argv 验证的遗留候选进程，再在 `127.0.0.1:2481` 启动隔离候选实例。候选的历史和审计数据使用独立临时路径，不读取、迁移或改写正式数据。安装器先通过 HTTPS `/healthz` 核对 commit 和产物摘要，再从 `/dev/tty` 重新读取密码，在单独的 Python 进程内实际验证登录、Secure Cookie、CSRF 会话、核心状态 API 和注销。密码不会进入 argv、环境变量、文件或日志。端口已被无法验证的进程占用时安全退出，不会盲目删除 PID 文件。
5. 只通过受验证的 PID 文件停止旧服务，原子替换生产文件，并验证正式 `2480` 实例。
6. 写入持久启动包装器和 EOS `codex-webui-start` on-boot event-handler。安装过程中不会重启交换机。

切换阶段失败时，安装器会恢复旧应用、旧启动包装器和旧 event-handler。先前版本属于受管 HTTPS 服务时会自动重启并验证；首次从无认证 HTTP 旧版迁移时只恢复文件，旧监听器会故意保持停止，避免在管理网络重新暴露不安全服务。若自动恢复无法验证，则保留恢复文件并打印明确的人工恢复路径。应用备份最多保留两份。

### 从旧版无 PID 文件部署迁移

安装器绝不会使用 `pkill -f`。如果旧服务正在运行但没有受管 PID 文件，请先确认它的准确 PID，再通过 `LEGACY_PID` 显式授权本次迁移：

```sh
ps -ef | grep '[a]rista7050_web.py'
sudo -n env REF="$REF" ARTIFACT_SHA="$ARTIFACT_SHA" LEGACY_PID=<verified-pid> \
  sh /tmp/arista-dashboard-install.sh
```

安装器会再次读取 `/proc/<pid>/cmdline`；该文件必须可读，并且其中必须存在与当前 `APP_PATH` 完全相等的 argv 项，才会采用并终止该 PID。子串匹配不会通过。若存在多个实例，请先人工查明原因，不要猜测 PID。

### 可配置项

所有选项都有安全默认值；常用覆盖项如下：

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `HOST` / `PORT` | `$TLS_IP` / `2480` | 正式 HTTPS 监听地址和端口，默认仅绑定管理 IP；端口必须为 1–65535 |
| `CANDIDATE_PORT` | `2481` | 仅 `127.0.0.1` 候选验证端口；必须与正式端口不同 |
| `TLS_IP` / `TLS_HOSTNAME` | `192.168.0.248` / `Arista7050` | 自签名证书 SAN |
| `AUTH_USER` | `admin` | 初始化的 Dashboard 用户名 |
| `ROTATE_AUTH` | `0` | 设为 `1`/`true`/`yes` 时重新提示并写入密码摘要 |
| `STARTUP` | `1` | 设为 `0`/`false`/`no` 时不修改 EOS on-boot handler |
| `MIN_FREE_KB` | `8192` | 部署前最低可用闪存空间 |
| `MAX_LOG_BYTES` | `2097152` | 启动时轮转日志的大小阈值；只保留 `.1` |
| `STATE_DIR` | `/persist/secure/arista-dashboard` | 权限为 `0700` 的安全持久目录；保存密钥、认证、PID、包装器、历史、审计和日志 |
| `INSTALL_LOCK` | `$STATE_DIR/install.lock` | 安装器并发锁目录；仅自动清除确认没有存活 owner PID 的旧锁 |

布尔变量只接受表中列出的真值以及对应的 `0`/`false`/`no`，拼写错误会直接失败。路径及标识符仅允许安全字符，避免把未经转义的内容写入启动脚本或 EOS 配置。

## 首次访问与证书信任

首次打开：

```text
https://192.168.0.248:2480/
```

浏览器会提示自签名证书不受信任。先在交换机控制台核对 SHA-256 指纹：

```sh
openssl x509 -in /persist/secure/arista-dashboard/dashboard.crt \
  -noout -subject -fingerprint -sha256
openssl x509 -in /persist/secure/arista-dashboard/dashboard.crt -noout -text \
  | sed -n '/Subject Alternative Name/{n;p;}'
```

确认 IP、主机名和指纹后，可将证书导入管理终端的受信任证书存储，或仅为该管理地址建立受控例外。不要绕过一个未核对指纹的证书警告。普通 HTTP 页面不会作为降级路径提供。

## 凭据轮换

EOS 密码变更后，使用当前已验证的同一 commit/SHA 重新运行安装器，并设置 `ROTATE_AUTH=1`：

```sh
REF=<currently-deployed-commit>
ARTIFACT_SHA=<currently-deployed-artifact-sha>
sudo -n env REF="$REF" ARTIFACT_SHA="$ARTIFACT_SHA" ROTATE_AUTH=1 \
  sh /tmp/arista-dashboard-install.sh
```

安装器会在 `/dev/tty` 重新提示密码，完成候选验证后再切换服务。不要通过 `WEB_PASSWORD`、Shell 历史或 URL 传递密码。

当前固定版本可在交换机上查看：

```sh
sudo -n cat /persist/secure/arista-dashboard/release
```

## 回滚与运维

- 部署失败时安装器自动回滚；无需也不应重启交换机。从无认证 HTTP 旧版首次迁移失败时，旧文件会恢复但旧网络服务不会自动重启。
- 已完成部署需要回退时，继续使用当前已审核的安装器脚本，把 `REF`、`ARTIFACT_SHA` 和（如需覆盖）`APP_URL` 指向目标旧产物。不要改为执行旧 commit 中可能缺少安全检查的 `install.sh`。目标旧产物仍须支持当前的 HTTPS、认证、PID 和版本参数，否则候选验证会安全失败；跨不兼容版本应先在实验环境验证。
- 应用备份位于 `/mnt/flash/arista7050_web.py.bak.<UTC timestamp>.<installer PID>`，最多保留最近两份。
- 运行日志为 `/persist/secure/arista-dashboard/dashboard.log`；超过阈值时启动包装器将其轮转为单个 `.1` 文件。
- 进程 PID 位于 `/persist/secure/arista-dashboard/dashboard.pid`。运维时只能在核对 `/proc/<pid>/cmdline` 后操作该 PID，禁止使用宽泛的 `pkill`。
- 安装器会保存并更新 EOS event-handler，但不会执行设备重启。可用以下命令静态检查：

```text
show running-config section event-handler codex-webui-start
```

使用当前安全安装器部署一个兼容的旧产物时，可显式分离“安装器版本”和“目标应用版本”：

```sh
INSTALLER_REF=<reviewed-commit-containing-current-installer>
TARGET_REF=<40-character-compatible-target-commit>
TARGET_SHA=<target-onbox-sha256>
curl -fL "https://raw.githubusercontent.com/ZONGRUICHD/Arista-Switch-Web-Dashboard/$INSTALLER_REF/install.sh" \
  -o /tmp/arista-dashboard-install.sh
sudo -n env REF="$TARGET_REF" ARTIFACT_SHA="$TARGET_SHA" \
APP_URL="https://raw.githubusercontent.com/ZONGRUICHD/Arista-Switch-Web-Dashboard/$TARGET_REF/onbox/arista7050_web.py" \
  sh /tmp/arista-dashboard-install.sh
```

## API 变化

除 `/healthz` 外，API 需要有效登录会话。除建立登录会话本身外，所有写请求（包括注销和解锁）还必须携带当前会话的 CSRF token。`/healthz` 只暴露健康状态、版本和产物摘要。

| 方法和路径 | 行为 |
| --- | --- |
| `POST /api/auth/login` | 建立登录会话 |
| `POST /api/auth/logout` | 注销并清除会话 |
| `GET /api/auth/session` | 获取登录、CSRF 和临时解锁状态 |
| `POST /api/auth/unlock` | 重新验证密码并解锁配置操作 15 分钟 |
| `POST /api/diagnostics` | 执行固定诊断 ID；不接受原始 CLI 文本 |
| `POST /api/config/preview` | 校验动作并生成命令、差异、基线哈希和短期 token |
| `POST /api/config/apply` | 校验 CSRF、解锁状态和 token，取得 EOS transaction lock，复核基线后事务提交 |

旧的 `POST /api/command` 和 `POST /api/config` 返回 `410 Gone`，调用方必须迁移，不能依赖旧的前缀命令过滤或 `confirm: "APPLY"` 协议。现有只读状态接口保留其主要数据结构，并额外提供版本、数据来源、分区更新时间和 stale/error 元数据。

## EOS control-plane ACL

若交换机本机访问正常但管理电脑连接 TCP/2480 超时，请检查现有 control-plane ACL。不要创建只包含 2480 的新 ACL 后直接替换 `default-control-plane-acl`，否则可能同时阻断 SSH、SNMP 和路由协议。应先完整保留现有规则，再按组织的来源网段策略增加 TCP/2480；优先限制到专用管理网段，而不是 `any`。

本机 eAPI 建议保持仅 localhost/Unix socket，不向管理网络新增 eAPI HTTP/HTTPS 监听：

```text
configure terminal
management api http-commands
   no protocol http
   no protocol https
   protocol http localhost
   protocol unix-socket
   no shutdown
end
```

在生产交换机上提交任何配置前，先在实验环境验证对应 EOS 版本、硬件型号、configuration session 行为和回滚路径。
