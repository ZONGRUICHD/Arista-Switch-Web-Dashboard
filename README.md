# Arista 管理口 Web 界面

## 部署方法

在交换机上进入 enable 和 bash：

```text
enable
bash
```

一条命令安装或更新 WebUI：

```text
curl -fsSL https://raw.githubusercontent.com/zong1024/Arista-Management-Port-Web-Interface/master/install.sh | sh
```

自定义端口或分支：

```text
curl -fsSL https://raw.githubusercontent.com/zong1024/Arista-Management-Port-Web-Interface/master/install.sh | PORT=2480 BRANCH=master sh
```

可选开启 Basic 登录认证：

```text
curl -fsSL https://raw.githubusercontent.com/zong1024/Arista-Management-Port-Web-Interface/master/install.sh | WEB_USERNAME=admin WEB_PASSWORD=你的密码 sh
```

如需从 EOS control-plane ACL 放行 TCP/2480：

```text
configure terminal
ip access-list codex-web-2480-cp
   5 permit tcp any any eq 2480
system control-plane
   ip access-group codex-web-2480-cp in
write memory
```

打开 WebUI：

```text
http://交换机IP:2480/
```

实现方式：WebUI 是部署在交换机 `/mnt/flash` 的 on-box Python 程序，运行时在 EOS bash 里通过本机 `Cli` / `FastCli` 执行只读 `show` 命令和受控配置模板；不是 eAPI，也不是外部 SSH 代理服务。安装脚本只是用 curl 下载文件并重启 WebUI 进程，默认不修改交换机配置。

## TODO

### 已完成

- [x] 单文件 on-box WebUI，可直接在 Arista EOS 上通过 Python 运行。
- [x] HTTP 服务监听 TCP/2480。
- [x] 仪表盘页面：主机名、EOS 版本、CPU、内存、温度、风扇、电源、告警、事件、集成状态。
- [x] 独立端口视图页面：`/ports`。
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
- [x] 光模块基础采集：`show interfaces transceiver` / detail。
- [x] 光模块 DOM 字段解析：温度、TX/RX 光功率、序列号、厂商、型号、阈值/告警原始行。
- [x] 支持机型的 PoE 状态采集和 PoE 启停模板。
- [x] 接口计数器历史持久化到服务端 JSON，并用于更长时间范围折线图。
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

### 部分完成 / 需要更多验证

- [ ] 在更多 EOS 版本和交换机型号上验证所有读取解析器。
- [ ] 验证 LLDP 输出中系统名、Chassis ID、端口 ID 包含空格时的解析。
- [ ] 改进 OSPF、OSPFv3、BGP 的解析，不只依赖 summary 简表。
- [ ] 改进 VLAN、ARP、FDB 大表分页和前端渲染性能。
- [x] 将流量历史持久化到服务端，而不是只保存在浏览器内存中。
- [x] 生产使用前增加 WebUI 登录认证。
- [ ] 增加只读用户和运维用户的权限区分。
- [x] 为每一次配置操作增加完整审计日志。
- [ ] 增加配置操作回滚辅助能力。
- [ ] 通过 EOS event-handler 或受支持的启动机制实现开机自启。
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
- [ ] SVI 创建和网关校验流程。
- [x] OSPF area/interface 配置流程。
- [ ] BGP address-family 和 route-policy 配置流程。
- [ ] 基于 EOS 命令样本的单元测试。
- [ ] 浏览器 UI 回归测试。
- [ ] 打包和 release 产物。

生产提醒：很多功能只在有限环境中测试过。用于生产交换机前，请先在实验环境中验证命令、解析逻辑和写配置流程。
