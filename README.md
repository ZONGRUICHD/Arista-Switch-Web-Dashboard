# Arista 管理口 Web 界面

## 部署方法

如果通过交换机 Console 口操作，串口参数通常为 `9600 8N1`。例如本地 Windows 上可连接 `COM3` 后登录 EOS，再进入 `enable` 和 `bash`。

在交换机上进入 enable 和 bash：

```text
enable
bash
```

一条命令安装或更新 WebUI：

```text
curl -fsSL https://raw.githubusercontent.com/zong1024/Arista-Management-Port-Web-Interface/master/install.sh | sh
```

安装并设置开机自启动：

```text
curl -fsSL https://raw.githubusercontent.com/zong1024/Arista-Management-Port-Web-Interface/master/install.sh | STARTUP=1 sh
```

自定义端口或分支：

```text
curl -fsSL https://raw.githubusercontent.com/zong1024/Arista-Management-Port-Web-Interface/master/install.sh | PORT=2480 BRANCH=master sh
```

可选开启 Basic 登录认证：

```text
curl -fsSL https://raw.githubusercontent.com/zong1024/Arista-Management-Port-Web-Interface/master/install.sh | WEB_USERNAME=admin WEB_PASSWORD=你的密码 sh
```

如果交换机本机 `curl http://127.0.0.1:2480/` 正常，但电脑访问 `http://交换机IP:2480/` 超时，通常是 EOS control-plane ACL 未放行 TCP/2480。不要把只包含 2480 的 ACL 直接绑定到 `system control-plane`，否则可能替换默认控制面 ACL，影响 SSH、SNMP、路由协议等管理/控制流量。推荐先复制当前 `default-control-plane-acl` 的规则，再额外插入 TCP/2480：

```text
show ip access-lists default-control-plane-acl
configure terminal
ip access-list codex-web-2480-cp
   counters per-entry
   ! 先复制 default-control-plane-acl 中的现有 permit 规则
   75 permit tcp any any eq 2480
system control-plane
   ip access-group codex-web-2480-cp in
end
write memory
```

打开 WebUI：

```text
http://交换机IP:2480/
```

实现方式：WebUI 是部署在交换机 `/mnt/flash` 的 on-box Python 程序。状态采集优先使用本机 eAPI `http://localhost:8080/command-api` 的 JSON 输出，eAPI 不可用或命令不支持时自动回退到本机 `Cli` / `FastCli` 文本输出；受控配置模板仍通过 EOS CLI 执行。安装脚本只是用 curl 下载文件并重启 WebUI 进程，默认不修改交换机配置。设置 `STARTUP=1` 时会创建 EOS `event-handler`，在开机后延迟 60 秒启动 WebUI。

推荐只启用本机 eAPI，不对管理网开放 eAPI HTTP/HTTPS：

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

## 故障排查

### `chmod: Operation not permitted`

部分 EOS 版本或 flash 挂载方式会拒绝修改 `/mnt/flash` 中文件的执行权限，例如：

```text
chmod: changing permissions of '/mnt/flash/arista7050_web.py.download.4334': Operation not permitted
```

WebUI 是通过 `python3 /mnt/flash/arista7050_web.py` 启动的，不依赖文件可执行位。安装脚本会在 `chmod` 失败时打印警告并继续完成编译、替换和启动。

## TODO

### 已完成

- [x] 单文件 on-box WebUI，可直接在 Arista EOS 上通过 Python 运行。
- [x] HTTP 服务监听 TCP/2480。
- [x] 仪表盘页面：主机名、EOS 版本、CPU、内存、温度、风扇、电源、告警、事件、集成状态。
- [x] 独立端口视图页面：`/ports`。
- [x] QSFP 4x10G breakout 聚合显示：端口页按物理 QSFP 卡片展示，点开后查看每条 10G lane。
- [x] 端口颜色状态：Up、Down、有介质、Error。
- [x] 端口详情弹窗：状态、VLAN、双工、协商速率、介质类型、RX/TX Mbps、Kpps、错误计数、EOS 原始输出行。
- [x] 端口详情中的 RX/TX 折线图。
- [x] 全局接口流量汇总折线图。
- [x] 深色模式开关，并在浏览器本地记忆选择。
- [x] VLAN 表采集：`show vlan brief`。
- [x] ARP 表采集：`show arp`。
- [x] FDB/MAC 地址表采集：`show mac address-table`。
- [x] LLDP 邻居采集：`show lldp neighbors`。
- [x] OSPF、OSPFv3、BGP summary 采集。
- [x] 基础告警生成：环境异常、风扇/电源异常、温度偏高、接口错误计数、有介质但链路未 Up、采集失败。
- [x] Syslog、sFlow、NetFlow/IPFIX 配置探测。
- [x] 只读命令控制台，并拦截写入/删除/重启等危险命令。
- [x] 受控配置 API，执行前必须传入 `confirm: "APPLY"`。
- [x] 配置操作 dry-run 预览。
- [x] 配置模板：端口启停、接口描述、创建 VLAN、接口加入 VLAN、三层接口、OSPF network、BGP neighbor。
- [x] 光模块基础采集：`show interfaces transceiver` / `csv` / `properties` / detail，并结合 `show inventory` 补全厂商、型号、序列号。
- [x] 光模块 DOM 字段解析：温度、TX/RX 光功率、阈值/告警原始行，避免把 DOM 数值行误显示为模块类型。
- [x] 支持机型的 PoE 状态采集和 PoE 启停模板。
- [x] 接口计数器历史持久化到服务端 JSON，并用于更长时间范围折线图。
- [x] 读取采集优先使用本机 eAPI JSON，eAPI 不支持的命令自动回退 CLI。
- [x] 渐进式加载：首屏优先加载核心设备和端口数据，再补健康、LLDP、表格、光模块和协议数据。
- [x] 右上角可调整自动刷新间隔，支持手动、5 秒、10 秒、15 秒、30 秒、60 秒。
- [x] 可选 WebUI Basic 登录认证：通过 `WEB_USERNAME` / `WEB_PASSWORD` 开启。
- [x] 为每一次配置操作记录审计日志。
- [x] 每次写配置前后的 running-config diff。
- [x] 可选 HTTPS/TLS：通过 `--tls-cert` / `--tls-key` 或环境变量开启。
- [x] 带二次确认的保存配置动作：`save_config` / `write memory`。
- [x] VLAN trunk 配置模板。
- [x] SVI 创建模板。
- [x] OSPF interface area 配置模板。
- [x] BGP address-family activate/deactivate 模板。
- [x] 一条命令安装/更新脚本：`install.sh`。
- [x] 通过 EOS event-handler 设置开机自启动。

### 部分完成 / 需要更多验证

- [ ] 在更多 EOS 版本和交换机型号上验证所有读取解析器。
- [x] 验证 LLDP 输出中系统名、Chassis ID、端口 ID 包含空格时的解析。
- [ ] 改进 OSPF、OSPFv3、BGP 的解析，不只依赖 summary 简表。
- [ ] 改进 VLAN、ARP、FDB 大表分页和前端渲染性能。
- [x] 将流量历史持久化到服务端，而不是只保存在浏览器内存中。
- [x] 生产使用前增加 WebUI 登录认证。
- [ ] 增加只读用户和运维用户的权限区分。
- [x] 为每一次配置操作增加完整审计日志。
- [ ] 增加配置操作回滚辅助能力。
- [x] 通过 EOS event-handler 或受支持的启动机制实现开机自启。
- [ ] 在实验环境中完整验证所有受控写操作。

### 未完成

- [x] PoE 状态查看和 PoE 控制。
- [x] 光模块详情页：基于 `show interfaces transceiver`。
- [x] 光功率、DOM 温度、序列号、厂商、阈值告警。
- [x] 接口计数器历史存储和更长时间范围的图表。
- [ ] 可拖拽/可自定义的仪表盘组件。
- [ ] 多设备自动发现。
- [ ] 多设备拓扑图。
- [ ] Syslog 接收器集成。
- [ ] NetFlow/sFlow/IPFIX Collector 集成。
- [ ] 告警通知渠道。
- [ ] 用户登录和会话管理。
- [x] HTTPS/TLS 支持。
- [x] 每次写配置前后的 diff。
- [x] 带二次确认的保存配置按钮。
- [x] VLAN trunk 配置模板。
- [x] SVI 创建和网关校验流程。
- [x] OSPF area/interface 配置流程。
- [ ] BGP address-family 和 route-policy 配置流程。
- [x] 基于 EOS 命令样本的单元测试。
- [ ] 浏览器 UI 回归测试。
- [ ] 打包和 release 产物。

生产提醒：很多功能只在有限环境中测试过。用于生产交换机前，请先在实验环境中验证命令、解析逻辑和写配置流程。
