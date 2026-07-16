(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const ROUTES = {
    "/": "overview",
    "/ports": "ports",
    "/network": "network",
    "/diagnostics": "diagnostics",
    "/changes": "changes"
  };
  const REFRESH_SCOPES = ["core", "metrics", "health", "tables", "discovery", "optics", "protocols", "extras"];
  const DIAGNOSTICS = [
    ["version", "系统版本", "EOS、硬件型号、序列号和运行时间"],
    ["interfaces_status", "端口状态", "所有接口的链路、VLAN、双工和速率"],
    ["vlan", "VLAN", "VLAN 清单和成员端口"],
    ["lldp", "LLDP 邻居", "相邻设备和连接端口"],
    ["environment", "环境传感器", "温度、风扇和电源状态"],
    ["routes", "路由表", "当前 IPv4 路由摘要"],
    ["arp", "ARP", "IPv4 邻居解析表"],
    ["mac_table", "MAC 地址表", "二层转发表"],
    ["transceivers", "光模块", "收发器识别与 DOM 数据"],
    ["ping", "Ping", "向受限目标发送 ICMP 探测"],
    ["traceroute", "Traceroute", "追踪到受限目标的路径"]
  ];
  const CHANGE_ACTIONS = {
    interface_admin: {
      label: "启用或停用接口",
      description: "改变一个物理或逻辑接口的管理状态。停用可能立即中断流量。",
      fields: [field("interface", "接口", "text", "Ethernet1"), choice("state", "状态", [["enable", "启用"], ["disable", "停用"]])]
    },
    poe_control: {
      label: "PoE 控制",
      description: "为指定端口启用或停用 PoE 供电。",
      fields: [field("interface", "接口", "text", "Ethernet1"), choice("state", "状态", [["enable", "启用"], ["disable", "停用"]])]
    },
    description: {
      label: "接口描述",
      description: "更新接口描述，便于资产和链路识别。",
      fields: [field("interface", "接口", "text", "Ethernet1"), field("description", "描述", "text", "rack-01 server uplink")]
    },
    access_vlan: {
      label: "Access VLAN",
      description: "将接口设为 access 模式并分配一个 VLAN。",
      fields: [field("interface", "接口", "text", "Ethernet1"), field("vlan", "VLAN ID", "number", "100", { min: 1, max: 4094 })]
    },
    trunk_vlan: {
      label: "Trunk VLAN",
      description: "将接口设为 trunk，并配置允许的 VLAN 列表和可选 native VLAN。",
      fields: [field("interface", "接口", "text", "Ethernet1"), field("vlan", "允许的 VLAN", "text", "10,20,100-120"), field("nativeVlan", "Native VLAN（可选）", "number", "10", { min: 1, max: 4094, required: false })]
    },
    create_vlan: {
      label: "创建 VLAN",
      description: "创建 VLAN，并可设置便于识别的名称。",
      fields: [field("vlan", "VLAN ID", "number", "100", { min: 1, max: 4094 }), field("name", "名称（可选）", "text", "SERVERS", { required: false })]
    },
    svi_interface: {
      label: "配置 SVI",
      description: "为 VLAN 接口配置 IPv4 地址和可选描述。",
      fields: [field("vlan", "VLAN ID", "number", "100", { min: 1, max: 4094 }), field("address", "IPv4 前缀", "text", "192.0.2.1/24"), field("description", "描述（可选）", "text", "server gateway", { required: false })]
    },
    l3_interface: {
      label: "三层接口",
      description: "关闭二层交换模式，并为接口配置 IPv4 地址。",
      fields: [field("interface", "接口", "text", "Ethernet1"), field("address", "IPv4 前缀", "text", "192.0.2.1/31")]
    },
    ospf_network: {
      label: "OSPF 网络",
      description: "向指定 OSPF 进程添加一个网络和区域。",
      fields: [field("process", "进程 ID", "number", "1", { min: 1, max: 65535 }), field("network", "网络前缀", "text", "192.0.2.0/24"), field("area", "区域", "text", "0")]
    },
    ospf_interface: {
      label: "OSPF 接口",
      description: "在接口上启用指定 OSPF 区域。",
      fields: [field("interface", "接口", "text", "Ethernet1"), field("area", "区域", "text", "0")]
    },
    bgp_neighbor: {
      label: "BGP 邻居",
      description: "为本地 ASN 添加 IPv4 邻居及其远端 ASN。",
      fields: [field("asn", "本地 ASN", "number", "65001", { min: 1 }), field("neighbor", "邻居 IPv4", "text", "192.0.2.2"), field("remoteAs", "远端 ASN", "number", "65002", { min: 1 })]
    },
    bgp_address_family: {
      label: "BGP 地址族",
      description: "在 BGP 地址族中启用或停用一个邻居。",
      fields: [field("asn", "本地 ASN", "number", "65001", { min: 1 }), field("neighbor", "邻居 IP", "text", "192.0.2.2"), choice("addressFamily", "地址族", [["ipv4", "IPv4"], ["ipv6", "IPv6"]]), choice("mode", "状态", [["activate", "启用"], ["deactivate", "停用"]])]
    },
    save_config: {
      label: "保存运行配置",
      description: "将当前 running-config 保存为 startup-config。",
      fields: []
    }
  };

  const elements = {
    loginView: $("loginView"), loginForm: $("loginForm"), loginUsername: $("loginUsername"), loginPassword: $("loginPassword"), loginError: $("loginError"),
    appShell: $("appShell"), deviceHostname: $("deviceHostname"), deviceModel: $("deviceModel"), connectionBadge: $("connectionBadge"), lastRefresh: $("lastRefresh"),
    refreshInterval: $("refreshInterval"), refreshButton: $("refreshButton"), unlockButton: $("unlockButton"), themeButton: $("themeButton"), logoutButton: $("logoutButton"),
    overviewState: $("overviewState"), portsState: $("portsState"), networkState: $("networkState"), alertsList: $("alertsList"), alertCount: $("alertCount"),
    healthMetrics: $("healthMetrics"), healthLabel: $("healthLabel"), metricPorts: $("metricPorts"), metricPortsNote: $("metricPortsNote"), metricEos: $("metricEos"), metricUptime: $("metricUptime"), metricTraffic: $("metricTraffic"), metricCapacity: $("metricCapacity"), metricForwarding: $("metricForwarding"), metricSource: $("metricSource"),
    trafficChart: $("trafficChart"), trafficChartDescription: $("trafficChartDescription"), trafficSummary: $("trafficSummary"), eventsList: $("eventsList"),
    portsSummary: $("portsSummary"), portSearch: $("portSearch"), portFilter: $("portFilter"), portGrid: $("portGrid"), portsEmpty: $("portsEmpty"),
    lldpCount: $("lldpCount"), lldpTable: $("lldpTable"), vlanTable: $("vlanTable"), protocolTable: $("protocolTable"), arpTable: $("arpTable"), fdbTable: $("fdbTable"), opticsTable: $("opticsTable"), poeSummary: $("poeSummary"), integrationsList: $("integrationsList"),
    diagnosticForm: $("diagnosticForm"), diagnosticCommand: $("diagnosticCommand"), diagnosticParams: $("diagnosticParams"), diagnosticRun: $("diagnosticRun"), diagnosticOutput: $("diagnosticOutput"), copyDiagnostic: $("copyDiagnostic"),
    lockStatus: $("lockStatus"), changeForm: $("changeForm"), changeAction: $("changeAction"), changeDescription: $("changeDescription"), changeFields: $("changeFields"), previewButton: $("previewButton"), previewOutput: $("previewOutput"), previewExpiry: $("previewExpiry"), applyBar: $("applyBar"), confirmApply: $("confirmApply"), applyButton: $("applyButton"),
    drawerBackdrop: $("drawerBackdrop"), portDrawer: $("portDrawer"), drawerTitle: $("drawerTitle"), drawerBody: $("drawerBody"), drawerClose: $("drawerClose"),
    unlockLayer: $("unlockLayer"), unlockDialog: $("unlockDialog"), unlockClose: $("unlockClose"), unlockForm: $("unlockForm"), unlockPassword: $("unlockPassword"), unlockError: $("unlockError"),
    toastRegion: $("toastRegion")
  };

  const app = {
    session: { authenticated: false, csrfToken: "", user: "", unlockedUntil: 0 },
    data: {},
    refreshGeneration: 0,
    refreshController: null,
    refreshPromise: null,
    refreshTimer: null,
    lockTimer: null,
    scopeErrors: new Map(),
    portCards: [],
    portByKey: new Map(),
    preview: null,
    previewGeneration: 0,
    previousFocus: null,
    drawerCloseTimer: null
  };

  class ApiError extends Error {
    constructor(message, status, code) {
      super(message);
      this.name = "ApiError";
      this.status = status;
      this.code = code;
    }
  }

  function field(name, label, type, placeholder, options = {}) {
    return { name, label, type, placeholder, required: options.required !== false, min: options.min, max: options.max };
  }

  function choice(name, label, options) {
    return { name, label, type: "select", options, required: true };
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function asArray(value) {
    if (Array.isArray(value)) return value;
    if (value && typeof value === "object") return Object.values(value);
    return [];
  }

  function numeric(value, fallback = 0) {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  }

  function clamp(value, min, max) {
    return Math.min(max, Math.max(min, numeric(value)));
  }

  function valueFrom(row, keys, fallback = "—") {
    for (const key of keys) {
      const value = key.split(".").reduce((current, part) => current && current[part], row);
      if (value !== undefined && value !== null && value !== "") return value;
    }
    return fallback;
  }

  function formatTime(value, withDate = false) {
    if (!value) return "—";
    const date = new Date(typeof value === "number" && value < 10_000_000_000 ? value * 1000 : value);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat("zh-CN", {
      month: withDate ? "2-digit" : undefined,
      day: withDate ? "2-digit" : undefined,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false
    }).format(date);
  }

  function formatRate(value) {
    const mbps = numeric(value);
    if (mbps >= 1_000_000) return `${(mbps / 1_000_000).toFixed(2)} Tbps`;
    if (mbps >= 1_000) return `${(mbps / 1_000).toFixed(2)} Gbps`;
    return `${mbps.toFixed(mbps >= 100 ? 0 : 1)} Mbps`;
  }

  function mergeState(base, update) {
    if (!update || typeof update !== "object") return base;
    const merged = { ...(base || {}) };
    for (const [key, value] of Object.entries(update)) {
      if (value && typeof value === "object" && !Array.isArray(value) && merged[key] && typeof merged[key] === "object" && !Array.isArray(merged[key])) {
        merged[key] = mergeState(merged[key], value);
      } else {
        merged[key] = value;
      }
    }
    return merged;
  }

  function sessionPayload(payload) {
    const source = payload && payload.session ? payload.session : payload || {};
    const until = source.unlockedUntil || source.unlocked_until || 0;
    const untilMs = typeof until === "number" && until > 0 && until < 10_000_000_000 ? until * 1000 : until;
    return {
      authenticated: Boolean(source.authenticated ?? payload?.authenticated),
      csrfToken: source.csrfToken || source.csrf_token || payload?.csrfToken || "",
      user: source.user || source.username || payload?.user || "",
      unlockedUntil: untilMs ? new Date(untilMs).getTime() : 0
    };
  }

  async function api(path, options = {}) {
    const method = options.method || "GET";
    const headers = { Accept: "application/json", ...(options.headers || {}) };
    if (options.body !== undefined) headers["Content-Type"] = "application/json";
    if (method !== "GET" && path !== "/api/auth/login" && app.session.csrfToken) {
      headers["X-CSRF-Token"] = app.session.csrfToken;
    }
    const response = await fetch(path, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials: "same-origin",
      signal: options.signal
    });
    const text = await response.text();
    let payload = {};
    try { payload = text ? JSON.parse(text) : {}; } catch { payload = { error: text || `HTTP ${response.status}` }; }
    if (!response.ok || payload.ok === false) {
      const error = payload.error;
      const message = typeof error === "object" ? error.message : error;
      const code = payload.code || error?.code;
      if (response.status === 401 && code === "authentication_required" && path !== "/api/auth/login") showLogin();
      throw new ApiError(message || payload.message || `HTTP ${response.status}`, response.status, code);
    }
    return payload;
  }

  function toast(message, tone = "info") {
    const item = document.createElement("div");
    item.className = "toast";
    item.dataset.tone = tone;
    item.setAttribute("role", tone === "error" ? "alert" : "status");
    item.textContent = message;
    elements.toastRegion.append(item);
    window.setTimeout(() => item.remove(), 4200);
  }

  function setBusy(button, busy, busyLabel) {
    if (!button.dataset.label) button.dataset.label = button.textContent;
    button.disabled = busy;
    button.textContent = busy ? busyLabel : button.dataset.label;
    button.setAttribute("aria-busy", String(busy));
  }

  function showLogin(message = "") {
    stopTimers();
    clearTimeout(app.drawerCloseTimer);
    app.drawerCloseTimer = null;
    app.previewGeneration += 1;
    resetPreview();
    app.data = {};
    app.scopeErrors.clear();
    app.portCards = [];
    app.portByKey.clear();
    elements.unlockLayer.hidden = true;
    elements.unlockPassword.value = "";
    elements.unlockError.hidden = true;
    elements.portDrawer.classList.remove("open");
    elements.portDrawer.setAttribute("aria-hidden", "true");
    elements.portDrawer.setAttribute("inert", "");
    elements.portDrawer.hidden = true;
    elements.drawerBackdrop.hidden = true;
    document.body.classList.remove("has-overlay");
    app.previousFocus = null;
    app.session = { authenticated: false, csrfToken: "", user: "", unlockedUntil: 0 };
    elements.appShell.hidden = true;
    elements.loginView.hidden = false;
    elements.loginError.hidden = !message;
    elements.loginError.textContent = message;
    window.setTimeout(() => elements.loginUsername.focus(), 0);
  }

  function showApp() {
    elements.loginView.hidden = true;
    elements.appShell.hidden = false;
    renderSession();
    routeTo(location.pathname, false);
    scheduleTimers();
  }

  function isUnlocked() {
    return app.session.unlockedUntil > Date.now();
  }

  function renderSession() {
    const unlocked = isUnlocked();
    elements.lockStatus.className = `status-badge ${unlocked ? "safe" : "locked"}`;
    elements.lockStatus.innerHTML = `<i></i><span>${unlocked ? `已解锁 · ${Math.max(1, Math.ceil((app.session.unlockedUntil - Date.now()) / 60000))} 分钟` : "只读模式"}</span>`;
    elements.unlockButton.textContent = unlocked ? "操作已解锁" : "解锁操作";
    elements.unlockButton.classList.toggle("primary", unlocked);
  }

  function routeName(pathname) {
    const clean = pathname.length > 1 ? pathname.replace(/\/+$/, "") : "/";
    return ROUTES[clean] || "overview";
  }

  function routePath(name) {
    return Object.entries(ROUTES).find(([, route]) => route === name)?.[0] || "/";
  }

  function routeTo(pathname, push = true) {
    const route = routeName(pathname);
    document.querySelectorAll("[data-page]").forEach((page) => { page.hidden = page.dataset.page !== route; });
    document.querySelectorAll("[data-route]").forEach((link) => {
      if (link.dataset.route === route) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
    const canonicalPath = routePath(route);
    if (push && location.pathname !== canonicalPath) history.pushState({ route }, "", canonicalPath);
    document.title = `${document.querySelector(`[data-page="${route}"] h2`)?.textContent || "运维台"} · Arista 7050QX`;
    const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    window.scrollTo({ top: 0, behavior: reducedMotion ? "auto" : "smooth" });
  }

  function setSectionState(element, status, message) {
    element.dataset.status = status;
    element.setAttribute("aria-busy", String(status === "loading"));
    element.textContent = message;
  }

  function freshnessStatus() {
    if (app.data.meta?.stale === true) return "stale";
    const value = app.data.device?.lastRefresh;
    if (!value) return "loading";
    const time = new Date(value).getTime();
    return Number.isFinite(time) && Date.now() - time > 130_000 ? "stale" : "ready";
  }

  function updateSectionStates(activeScope = "") {
    const loading = app.refreshPromise && activeScope;
    const stale = freshnessStatus() === "stale";
    const coreError = app.scopeErrors.get("core") || app.scopeErrors.get("metrics");
    const overviewError = coreError || app.scopeErrors.get("health");
    const networkError = ["tables", "discovery", "optics", "protocols", "extras"].map((scope) => app.scopeErrors.get(scope)).find(Boolean);
    setSectionState(elements.overviewState, loading && ["core", "metrics", "health"].includes(activeScope) ? "loading" : overviewError ? "error" : stale ? "stale" : "ready", loading ? `正在加载 ${activeScope}` : overviewError ? "部分数据加载失败" : stale ? "数据已过期" : "数据已更新");
    setSectionState(elements.portsState, loading && ["core", "metrics"].includes(activeScope) ? "loading" : coreError ? "error" : stale ? "stale" : "ready", loading ? "正在加载端口" : coreError ? "端口数据加载失败" : stale ? "端口数据已过期" : "端口数据已更新");
    setSectionState(elements.networkState, loading && !["core", "metrics", "health"].includes(activeScope) ? "loading" : networkError ? "error" : stale ? "stale" : "ready", loading ? `正在加载 ${activeScope}` : networkError ? "部分网络数据失败" : stale ? "网络数据已过期" : "网络数据已更新");
  }

  async function refreshAll(options = {}) {
    const generation = ++app.refreshGeneration;
    if (app.refreshController) app.refreshController.abort();
    const controller = new AbortController();
    app.refreshController = controller;
    app.scopeErrors.clear();
    const run = (async () => {
      setBusy(elements.refreshButton, true, "刷新中");
      for (const scope of REFRESH_SCOPES) {
        if (generation !== app.refreshGeneration) return;
        updateSectionStates(scope);
        try {
          const payload = await api("/api/refresh", { method: "POST", body: { scope }, signal: controller.signal });
          if (generation !== app.refreshGeneration) return;
          app.data = mergeState(app.data, payload.state || payload.data || payload);
          renderAll();
        } catch (error) {
          if (error.name === "AbortError") return;
          app.scopeErrors.set(scope, error.message);
          if (!options.silent) toast(`${scope}: ${error.message}`, "error");
        }
      }
      if (!options.silent && !app.scopeErrors.size) toast("状态已刷新", "success");
    })();
    app.refreshPromise = run;
    try {
      await run;
    } finally {
      if (app.refreshGeneration === generation) {
        app.refreshPromise = null;
        app.refreshController = null;
        setBusy(elements.refreshButton, false, "刷新中");
        updateSectionStates();
      }
    }
  }

  function renderAll() {
    renderHeader();
    renderOverview();
    renderPorts();
    renderNetwork();
    updateSectionStates();
  }

  function renderHeader() {
    const device = app.data.device || {};
    elements.deviceHostname.textContent = device.hostname || "Arista 7050QX";
    elements.deviceModel.textContent = device.model || "DCS-7050QX";
    elements.lastRefresh.textContent = device.lastRefresh ? `更新 ${formatTime(device.lastRefresh)}` : "尚未刷新";
    const stale = freshnessStatus() === "stale";
    elements.connectionBadge.className = `status-badge ${stale ? "warning" : "live"}`;
    elements.connectionBadge.innerHTML = `<i></i><span>${stale ? "数据已过期" : "HTTPS 在线"}</span>`;
  }

  function renderOverview() {
    const device = app.data.device || {};
    const health = app.data.health || {};
    const traffic = app.data.traffic || {};
    const ports = asArray(app.data.ports);
    const alerts = asArray(app.data.alerts);
    const events = asArray(app.data.events);
    const up = ports.filter((port) => String(port.status).toLowerCase() === "up").length;
    const errors = ports.filter((port) => numeric(port.errors) > 0).length;
    const healthError = app.scopeErrors.get("health");
    const healthLoading = app.data.loading?.health;
    const healthReported = [health.cpu, health.memory, health.temperature].every((value) => value !== undefined && value !== null && Number.isFinite(Number(value))) && Boolean(health.fanStatus && health.psuStatus);
    const healthReady = !healthError && healthReported && (healthLoading === undefined || healthLoading === "done");

    elements.alertCount.textContent = alerts.length || healthReady ? String(alerts.length) : "—";
    elements.alertsList.className = "state-content alert-list";
    elements.alertsList.innerHTML = alerts.length ? alerts.map((alert) => {
      const severity = String(alert.severity || alert.level || "warning").toLowerCase();
      const title = alert.title || alert.message || alert.name || "设备告警";
      const detail = alert.detail || alert.description || alert.interface || severity;
      return `<article class="alert-item" data-severity="${escapeHtml(severity)}"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(detail)}</span></article>`;
    }).join("") : !healthReady
      ? `<div class="inline-empty"><strong>${healthError ? "部分告警源采集失败" : "仍在采集环境告警"}</strong><span>在健康采集完成前，不将空结果解释为无告警。</span></div>`
      : `<div class="inline-empty"><strong>当前没有活动告警</strong><span>系统未报告需要处理的异常。</span></div>`;

    elements.healthMetrics.className = "health-metrics";
    if (!healthReady) {
      elements.healthMetrics.innerHTML = `<div class="inline-empty"><strong>${healthError ? "健康数据采集失败" : "正在采集健康数据"}</strong><span>CPU、内存、温度、风扇和电源状态当前不可确认。</span></div>`;
      elements.healthLabel.className = `status-badge ${healthError ? "locked" : "neutral"}`;
      elements.healthLabel.innerHTML = `<i></i><span>${healthError ? "采集失败" : "状态未知"}</span>`;
    } else {
      const metrics = [
        ["CPU", health.cpu, 100, "%"],
        ["内存", health.memory, 100, "%"],
        ["温度", health.temperature, 90, "°C"],
        ["风扇", null, null, health.fanStatus],
        ["电源", null, null, health.psuStatus]
      ];
      elements.healthMetrics.innerHTML = metrics.map(([label, value, max, suffix]) => {
        const display = value === null ? suffix : `${numeric(value)}${suffix}`;
        const meter = value === null ? "" : `<progress max="${max}" value="${clamp(value, 0, max)}" aria-label="${label} ${display}"></progress>`;
        return `<div class="health-metric"><span>${label}</span><strong>${escapeHtml(display)}</strong>${meter}</div>`;
      }).join("");
      const healthBad = /check|fail|fault|bad/i.test(`${health.fanStatus} ${health.psuStatus}`) || numeric(health.temperature) >= 70;
      elements.healthLabel.className = `status-badge ${healthBad ? "warning" : "safe"}`;
      elements.healthLabel.innerHTML = `<i></i><span>${healthBad ? "需要检查" : "运行正常"}</span>`;
    }

    elements.metricPorts.textContent = `${up} / ${ports.length || "—"}`;
    elements.metricPortsNote.textContent = `${errors} 个端口有错误`;
    elements.metricEos.textContent = device.eosVersion || "—";
    elements.metricUptime.textContent = `运行时间 ${device.uptime || "—"}`;
    elements.metricTraffic.textContent = formatRate(numeric(traffic.rxMbps) + numeric(traffic.txMbps));
    elements.metricCapacity.textContent = `容量占用 ${numeric(traffic.capacityUtilization).toFixed(4)}%`;
    elements.metricForwarding.textContent = device.forwardingRate || traffic.packetRateLabel || "—";
    elements.metricSource.textContent = `数据源 ${device.source || app.data.meta?.source || "—"}`;

    elements.eventsList.className = "event-list";
    elements.eventsList.innerHTML = events.length ? events.slice(0, 50).map((event) => `<li class="event-item" data-level="${escapeHtml(event.level || "info")}"><time datetime="${escapeHtml(event.time || "")}">${escapeHtml(formatTime(event.time, true))} · ${escapeHtml(event.level || "info")}</time><span>${escapeHtml(event.message || event.title || "")}</span></li>`).join("") : `<li class="inline-empty"><strong>没有事件</strong><span>新的采集或配置事件会显示在这里。</span></li>`;
    drawTrafficChart();
  }

  function trafficPoints() {
    const current = app.data.traffic || {};
    const rows = asArray(app.data.history?.traffic).slice(-80).map((row) => ({
      time: row.time || row.timestamp,
      rx: numeric(row.rxMbps ?? row.rx),
      tx: numeric(row.txMbps ?? row.tx),
      total: numeric(row.totalMbps, numeric(row.rxMbps) + numeric(row.txMbps))
    }));
    if (!rows.length && (current.rxMbps || current.txMbps)) rows.push({ time: Date.now(), rx: numeric(current.rxMbps), tx: numeric(current.txMbps), total: numeric(current.rxMbps) + numeric(current.txMbps) });
    return rows;
  }

  function drawTrafficChart() {
    const canvas = elements.trafficChart;
    const rect = canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.round(rect.width * dpr);
    canvas.height = Math.round(rect.height * dpr);
    const context = canvas.getContext("2d");
    context.scale(dpr, dpr);
    const points = trafficPoints();
    const styles = getComputedStyle(document.body);
    const line = styles.getPropertyValue("--line").trim();
    const muted = styles.getPropertyValue("--muted").trim();
    const rxColor = styles.getPropertyValue("--accent").trim();
    const txColor = styles.getPropertyValue("--info").trim();
    const width = rect.width;
    const height = rect.height;
    const pad = { left: 4, right: 4, top: 12, bottom: 22 };
    context.clearRect(0, 0, width, height);
    context.strokeStyle = line;
    context.lineWidth = 1;
    for (let index = 0; index < 4; index += 1) {
      const y = pad.top + ((height - pad.top - pad.bottom) * index) / 3;
      context.beginPath(); context.moveTo(pad.left, y); context.lineTo(width - pad.right, y); context.stroke();
    }
    if (points.length) {
      const max = Math.max(1, ...points.flatMap((point) => [point.rx, point.tx]));
      const plot = (key, color) => {
        context.beginPath();
        points.forEach((point, index) => {
          const x = pad.left + (points.length === 1 ? 0 : (index / (points.length - 1)) * (width - pad.left - pad.right));
          const y = pad.top + (1 - point[key] / max) * (height - pad.top - pad.bottom);
          if (index === 0) context.moveTo(x, y); else context.lineTo(x, y);
        });
        context.strokeStyle = color; context.lineWidth = 2; context.lineJoin = "round"; context.lineCap = "round"; context.stroke();
      };
      plot("rx", rxColor); plot("tx", txColor);
      context.fillStyle = muted; context.font = `11px ${getComputedStyle(document.body).fontFamily}`;
      context.fillText(formatRate(max), pad.left, 10);
      const latest = points[points.length - 1];
      elements.trafficChartDescription.textContent = `流量图包含 ${points.length} 个采样点。最新接收 ${formatRate(latest.rx)}，发送 ${formatRate(latest.tx)}。`;
      elements.trafficSummary.innerHTML = `<span>RX ${escapeHtml(formatRate(latest.rx))}</span><span>TX ${escapeHtml(formatRate(latest.tx))}</span><span>峰值 ${escapeHtml(formatRate(max))}</span>`;
    } else {
      context.fillStyle = muted; context.font = `13px ${getComputedStyle(document.body).fontFamily}`; context.fillText("暂无流量历史", 12, height / 2);
      elements.trafficChartDescription.textContent = "暂无流量历史。";
      elements.trafficSummary.textContent = "等待下一次服务端采样。";
    }
  }

  function groupPorts(ports) {
    const groups = new Map();
    const output = [];
    ports.forEach((port, index) => {
      const name = String(port.name || port.interface || `port-${index}`);
      const match = name.match(/^Ethernet(\d+)\/(\d+)$/i);
      if (!match) {
        output.push({ ...port, name, key: name, kind: "port" });
        return;
      }
      const base = `Ethernet${match[1]}`;
      if (!groups.has(base)) {
        const group = { key: base, name: base, kind: "breakout", lanes: [], description: "Breakout 端口" };
        groups.set(base, group); output.push(group);
      }
      groups.get(base).lanes.push({ ...port, name, lane: Number(match[2]) });
    });
    return output.map((port) => {
      if (port.kind !== "breakout") return port;
      port.lanes.sort((a, b) => a.lane - b.lane);
      const up = port.lanes.filter((lane) => String(lane.status).toLowerCase() === "up").length;
      return {
        ...port,
        status: up ? "up" : "down",
        description: `${up}/${port.lanes.length} lanes up`,
        speed: `${port.lanes.length} × ${port.lanes[0]?.speed || "lane"}`,
        vlan: [...new Set(port.lanes.map((lane) => lane.vlan).filter(Boolean))].join(", ") || "—",
        media: [...new Set(port.lanes.map((lane) => lane.media).filter(Boolean))].join(", ") || "—",
        hasMedia: port.lanes.some((lane) => lane.hasMedia),
        rxMbps: port.lanes.reduce((total, lane) => total + numeric(lane.rxMbps), 0),
        txMbps: port.lanes.reduce((total, lane) => total + numeric(lane.txMbps), 0),
        errors: port.lanes.reduce((total, lane) => total + numeric(lane.errors), 0)
      };
    });
  }

  function renderPorts() {
    const allPorts = asArray(app.data.ports);
    const cards = groupPorts(allPorts);
    const search = elements.portSearch.value.trim().toLowerCase();
    const filter = elements.portFilter.value;
    const filtered = cards.filter((port) => {
      const haystack = [port.name, port.description, port.vlan, port.media, ...(port.lanes || []).map((lane) => `${lane.name} ${lane.description || ""}`)].join(" ").toLowerCase();
      const status = String(port.status || "down").toLowerCase();
      const matchesFilter = filter === "all" || filter === status || (filter === "errors" && numeric(port.errors) > 0) || (filter === "media" && port.hasMedia);
      return matchesFilter && (!search || haystack.includes(search));
    });
    app.portCards = filtered;
    app.portByKey = new Map(filtered.map((port) => [port.key || port.name, port]));
    const up = allPorts.filter((port) => String(port.status).toLowerCase() === "up").length;
    const errors = allPorts.filter((port) => numeric(port.errors) > 0).length;
    elements.portsSummary.textContent = `${up}/${allPorts.length || 0} 个逻辑端口 Up · ${cards.length} 个物理端口 · ${errors} 个错误`;
    elements.portGrid.className = "port-grid";
    elements.portGrid.innerHTML = filtered.map((port) => {
      const status = String(port.status || "down").toLowerCase();
      return `<button class="port-card" type="button" data-port-key="${escapeHtml(port.key || port.name)}" data-status="${escapeHtml(status)}" data-errors="${numeric(port.errors) > 0}" aria-label="查看 ${escapeHtml(port.name)} 详情，状态 ${escapeHtml(status)}">
        <span class="port-card-head"><strong>${escapeHtml(port.name)}</strong><span class="port-status-text">${escapeHtml(status)}</span></span>
        <span class="port-description">${escapeHtml(port.description || "未设置描述")}</span>
        <span class="port-meta"><span>${escapeHtml(port.speed || "—")}</span><span>VLAN ${escapeHtml(port.vlan || "—")}</span><span>${escapeHtml(port.media || "—")}</span></span>
        <span class="port-traffic"><span>RX ${escapeHtml(formatRate(port.rxMbps))}</span><span>TX ${escapeHtml(formatRate(port.txMbps))}</span></span>
      </button>`;
    }).join("");
    elements.portsEmpty.hidden = filtered.length > 0 || !allPorts.length;
    if (!allPorts.length) elements.portGrid.innerHTML = `<div class="empty-state"><strong>尚未收到端口数据</strong><span>刷新后仍为空时，请检查采集状态。</span></div>`;
  }

  function detailItem(label, value) {
    return `<div class="detail-item"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value ?? "—")}</strong></div>`;
  }

  function syncOverlayState() {
    const drawerOpen = !elements.portDrawer.hidden && (elements.portDrawer.classList.contains("open") || elements.portDrawer.getAttribute("aria-hidden") === "false");
    document.body.classList.toggle("has-overlay", drawerOpen || !elements.unlockLayer.hidden);
  }

  function openPortDrawer(port) {
    if (!port) return;
    clearTimeout(app.drawerCloseTimer);
    app.drawerCloseTimer = null;
    app.previousFocus = document.activeElement;
    elements.drawerTitle.textContent = `${port.name} 详情`;
    const optics = port.transceiver || {};
    const details = [
      ["状态", port.status], ["速率", port.speed], ["VLAN", port.vlan], ["双工", port.duplex],
      ["介质", port.media], ["RX", formatRate(port.rxMbps)], ["TX", formatRate(port.txMbps)], ["错误计数", numeric(port.errors)],
      ["描述", port.description], ["光模块", optics.present === false ? "Not present" : optics.type], ["厂商", optics.vendor], ["序列号", optics.serial],
      ["DOM 温度", optics.temperature], ["TX / RX 光功率", `${optics.txPower || "—"} / ${optics.rxPower || "—"}`]
    ];
    let lanes = "";
    if (port.lanes?.length) {
      lanes = renderTableMarkup("Breakout lane 明细", [
        ["Lane", (row) => row.name], ["状态", (row) => row.status], ["VLAN", (row) => row.vlan], ["速率", (row) => row.speed], ["RX", (row) => formatRate(row.rxMbps)], ["TX", (row) => formatRate(row.txMbps)], ["错误", (row) => numeric(row.errors)]
      ], port.lanes);
    }
    const raw = [port.statusLine, port.rateLine, port.errorLine, optics.raw].filter(Boolean).join("\n");
    elements.drawerBody.innerHTML = `<div class="detail-grid">${details.map(([label, value]) => detailItem(label, value)).join("")}</div>${lanes ? `<div class="table-region">${lanes}</div>` : ""}${raw ? `<pre tabindex="0">${escapeHtml(raw)}</pre>` : ""}`;
    elements.portDrawer.hidden = false;
    elements.portDrawer.removeAttribute("inert");
    elements.drawerBackdrop.hidden = false;
    elements.portDrawer.setAttribute("aria-hidden", "false");
    syncOverlayState();
    requestAnimationFrame(() => { elements.portDrawer.classList.add("open"); elements.drawerClose.focus(); });
  }

  function closePortDrawer() {
    if (elements.portDrawer.hidden) return;
    const restoreTarget = app.previousFocus?.isConnected ? app.previousFocus : $("mainContent");
    app.previousFocus = null;
    restoreTarget?.focus?.();
    elements.portDrawer.classList.remove("open");
    elements.portDrawer.setAttribute("aria-hidden", "true");
    elements.portDrawer.setAttribute("inert", "");
    syncOverlayState();
    clearTimeout(app.drawerCloseTimer);
    app.drawerCloseTimer = window.setTimeout(() => {
      elements.portDrawer.hidden = true;
      elements.drawerBackdrop.hidden = true;
      app.drawerCloseTimer = null;
    }, 220);
  }

  function renderTableMarkup(caption, columns, rows) {
    if (!rows.length) return `<div class="inline-empty"><strong>暂无数据</strong><span>采集完成后仍为空表示设备未报告记录。</span></div>`;
    return `<table class="data-table"><caption>${escapeHtml(caption)}</caption><thead><tr>${columns.map(([label]) => `<th scope="col">${escapeHtml(label)}</th>`).join("")}</tr></thead><tbody>${rows.map((row) => `<tr>${columns.map(([, getter]) => `<td>${escapeHtml(getter(row))}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
  }

  function renderTable(target, caption, columns, source) {
    const rows = asArray(source);
    target.className = "table-region";
    target.innerHTML = renderTableMarkup(caption, columns, rows);
  }

  function renderNetwork() {
    const lldp = asArray(app.data.lldp);
    const vlans = asArray(app.data.vlans);
    const arp = asArray(app.data.arp);
    const fdb = asArray(app.data.fdb);
    const optics = asArray(app.data.transceivers);
    const protocols = app.data.protocols || {};
    const protocolRows = Object.entries(protocols).flatMap(([protocol, rows]) => asArray(rows).map((row) => ({ ...row, protocol: protocol.toUpperCase() })));
    elements.lldpCount.textContent = `${lldp.length} 条`;
    renderTable(elements.lldpTable, "LLDP 邻居", [
      ["本地端口", (row) => valueFrom(row, ["localPort", "interface", "port"])], ["邻居", (row) => valueFrom(row, ["neighbor", "systemName", "neighborDevice", "chassisId"])], ["邻居端口", (row) => valueFrom(row, ["neighborPort", "portId", "portDescription"])], ["管理地址", (row) => valueFrom(row, ["managementAddress", "managementIp", "address"])], ["描述", (row) => valueFrom(row, ["description", "systemDescription"])]
    ], lldp);
    renderTable(elements.vlanTable, "VLAN", [
      ["ID", (row) => valueFrom(row, ["id", "vlan", "vlanId"])], ["名称", (row) => valueFrom(row, ["name"])], ["状态", (row) => valueFrom(row, ["status", "state"])], ["端口", (row) => valueFrom(row, ["ports", "interfaces"])]
    ], vlans);
    renderTable(elements.protocolTable, "路由协议", [
      ["协议", (row) => row.protocol], ["邻居", (row) => valueFrom(row, ["neighbor", "peer", "routerId"])], ["状态", (row) => valueFrom(row, ["state", "status"])], ["接口 / 前缀", (row) => valueFrom(row, ["interface", "prefixes", "network"])], ["时间", (row) => valueFrom(row, ["uptime", "duration", "deadTime"])]
    ], protocolRows);
    renderTable(elements.arpTable, "ARP", [
      ["IP", (row) => valueFrom(row, ["ip", "address", "ipAddress"])], ["MAC", (row) => valueFrom(row, ["mac", "macAddress"] )], ["接口", (row) => valueFrom(row, ["interface", "port"])], ["年龄", (row) => valueFrom(row, ["age", "ageSeconds"])]
    ], arp);
    renderTable(elements.fdbTable, "MAC 地址表", [
      ["VLAN", (row) => valueFrom(row, ["vlan", "vlanId"])], ["MAC", (row) => valueFrom(row, ["mac", "macAddress"])], ["类型", (row) => valueFrom(row, ["type", "entryType"])], ["端口", (row) => valueFrom(row, ["interface", "port", "destination"])]
    ], fdb);
    renderTable(elements.opticsTable, "光模块", [
      ["接口", (row) => valueFrom(row, ["interface", "name", "port"])], ["类型", (row) => valueFrom(row, ["type", "media", "partNumber"])], ["厂商", (row) => valueFrom(row, ["vendor", "manufacturer"])], ["温度", (row) => valueFrom(row, ["temperature"])], ["TX", (row) => valueFrom(row, ["txPower"])], ["RX", (row) => valueFrom(row, ["rxPower"])], ["告警", (row) => asArray(row.alerts).join(", ") || "—"]
    ], optics);
    const poe = app.data.poe || {};
    elements.poeSummary.textContent = poe.supported === false ? "此型号或当前 EOS 未报告 PoE 数据。" : `PoE：${asArray(poe.ports).length} 个端口有采集记录。`;
    const integrations = app.data.integrations || {};
    const integrationRows = [["Syslog", integrations.syslog], ["sFlow", integrations.sflow], ["NetFlow / IPFIX", integrations.netflow], ["Streaming telemetry", integrations.telemetry]];
    elements.integrationsList.className = "integration-list";
    elements.integrationsList.innerHTML = integrationRows.map(([label, enabled]) => `<div class="integration-item"><span>${label}</span><strong data-enabled="${Boolean(enabled)}">${enabled ? "已配置" : "未配置"}</strong></div>`).join("");
  }

  function renderDiagnosticFields() {
    const commandId = elements.diagnosticCommand.value;
    elements.diagnosticParams.innerHTML = ["ping", "traceroute"].includes(commandId) ? `<label for="diagnosticTarget">目标 IP 地址</label><input id="diagnosticTarget" name="target" type="text" placeholder="192.0.2.1 或 2001:db8::1" required pattern="[A-Fa-f0-9:.]+" />` : "";
  }

  function renderChangeFields() {
    const definition = CHANGE_ACTIONS[elements.changeAction.value];
    elements.changeDescription.textContent = definition.description;
    elements.changeFields.innerHTML = definition.fields.map((item) => {
      const required = item.required ? "required" : "";
      if (item.type === "select") {
        return `<label for="change-${escapeHtml(item.name)}">${escapeHtml(item.label)}<select id="change-${escapeHtml(item.name)}" name="${escapeHtml(item.name)}" ${required}>${item.options.map(([value, label]) => `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`).join("")}</select></label>`;
      }
      const min = item.min === undefined ? "" : `min="${item.min}"`;
      const max = item.max === undefined ? "" : `max="${item.max}"`;
      return `<label for="change-${escapeHtml(item.name)}">${escapeHtml(item.label)}<input id="change-${escapeHtml(item.name)}" name="${escapeHtml(item.name)}" type="${escapeHtml(item.type)}" placeholder="${escapeHtml(item.placeholder)}" ${min} ${max} ${required} /></label>`;
    }).join("");
    invalidatePreview();
  }

  function resetPreview() {
    app.preview = null;
    elements.previewOutput.textContent = "选择变更并填写参数。";
    elements.previewExpiry.textContent = "尚未生成预览";
    elements.applyBar.hidden = true;
    elements.confirmApply.checked = false;
    elements.applyButton.disabled = true;
  }

  function invalidatePreview() {
    app.previewGeneration += 1;
    resetPreview();
  }

  function changeRequest() {
    const entries = [...new FormData(elements.changeForm).entries()].map(([name, value]) => [name, String(value)]);
    const action = entries.find(([name]) => name === "action")?.[1] || "";
    const params = Object.fromEntries(entries.filter(([name]) => name !== "action"));
    return { action, params, snapshot: JSON.stringify(entries) };
  }

  function previewExpiryMs(value) {
    if (!value) return 0;
    if (typeof value === "number") return value < 10_000_000_000 ? value * 1000 : value;
    const parsed = new Date(value).getTime();
    return Number.isFinite(parsed) ? parsed : 0;
  }

  function setChangeRegionBusy(busy) {
    const region = elements.changeForm.closest(".change-layout");
    region?.setAttribute("aria-busy", String(busy));
    [...elements.changeForm.elements].forEach((control) => { control.disabled = busy; });
    elements.confirmApply.disabled = busy;
    elements.applyButton.disabled = busy || !app.preview || !elements.confirmApply.checked;
  }

  async function runDiagnostic(event) {
    event.preventDefault();
    const commandId = elements.diagnosticCommand.value;
    const target = $("diagnosticTarget")?.value.trim();
    setBusy(elements.diagnosticRun, true, "运行中");
    elements.diagnosticOutput.textContent = "正在执行预定义诊断…";
    try {
      const payload = await api("/api/diagnostics", { method: "POST", body: { commandId, params: target ? { target } : {} } });
      const output = typeof payload.output === "string" ? payload.output : JSON.stringify(payload.output ?? payload.result ?? payload, null, 2);
      elements.diagnosticOutput.textContent = output || "命令完成，没有文本输出。";
      elements.copyDiagnostic.disabled = false;
      toast("诊断已完成", "success");
    } catch (error) {
      elements.diagnosticOutput.textContent = `ERROR: ${error.message}`;
      elements.copyDiagnostic.disabled = true;
      toast(error.message, "error");
    } finally {
      setBusy(elements.diagnosticRun, false, "运行中");
    }
  }

  async function previewChange(event) {
    event.preventDefault();
    const request = changeRequest();
    const generation = ++app.previewGeneration;
    resetPreview();
    setBusy(elements.previewButton, true, "生成中");
    elements.previewOutput.textContent = "正在生成配置会话与差异…";
    try {
      const payload = await api("/api/config/preview", { method: "POST", body: { action: request.action, params: request.params } });
      if (generation !== app.previewGeneration || request.snapshot !== changeRequest().snapshot) return;
      const token = payload.previewToken || payload.preview_token;
      if (!token) throw new Error("服务端未返回 preview token。");
      app.preview = { token, action: request.action, snapshot: request.snapshot, expiresAt: payload.expiresAt || payload.expires_at || 0 };
      const commands = asArray(payload.commands).join("\n");
      const diff = payload.diff || "（运行配置未产生可显示的差异）";
      elements.previewOutput.textContent = `COMMANDS\n${commands || "—"}\n\nDIFF\n${diff}\n\nBASELINE\n${payload.baselineHash || payload.baseline_hash || "—"}`;
      elements.previewExpiry.textContent = app.preview.expiresAt ? `预览有效至 ${formatTime(app.preview.expiresAt)}` : "短期预览令牌已生成";
      elements.applyBar.hidden = false;
      elements.confirmApply.checked = false;
      elements.applyButton.disabled = true;
      toast("预览已生成，请核对差异", "success");
    } catch (error) {
      if (generation !== app.previewGeneration) return;
      resetPreview();
      elements.previewOutput.textContent = `ERROR: ${error.message}`;
      toast(error.message, "error");
    } finally {
      setBusy(elements.previewButton, false, "生成中");
    }
  }

  async function applyChange() {
    if (!app.preview || !elements.confirmApply.checked) return;
    if (app.preview.snapshot !== changeRequest().snapshot) {
      invalidatePreview();
      toast("变更参数已修改，请重新生成预览", "error");
      return;
    }
    if (previewExpiryMs(app.preview.expiresAt) && previewExpiryMs(app.preview.expiresAt) <= Date.now()) {
      invalidatePreview();
      toast("配置预览已过期，请重新生成", "error");
      return;
    }
    if (!isUnlocked()) {
      openUnlockDialog();
      toast("先解锁配置操作", "error");
      return;
    }
    const preview = app.preview;
    setBusy(elements.applyButton, true, "提交中");
    setChangeRegionBusy(true);
    try {
      const payload = await api("/api/config/apply", { method: "POST", body: { previewToken: preview.token } });
      const commands = asArray(payload.commands).join("\n");
      elements.previewOutput.textContent = `APPLIED\n${commands || preview.action}\n\n${payload.diff || ""}\n\n${payload.output || "配置已提交。"}`;
      elements.previewExpiry.textContent = "配置已提交";
      elements.applyBar.hidden = true;
      app.preview = null;
      app.previewGeneration += 1;
      toast("配置已提交", "success");
      refreshAll({ silent: true });
    } catch (error) {
      if (["preview_expired", "preview_not_found", "config_changed"].includes(error.code)) {
        invalidatePreview();
        elements.previewOutput.textContent = `ERROR: ${error.message}`;
      } else {
        elements.previewOutput.textContent += `\n\nERROR\n${error.message}`;
      }
      toast(error.message, "error");
    } finally {
      setBusy(elements.applyButton, false, "提交中");
      setChangeRegionBusy(false);
    }
  }

  function focusable(container) {
    return [...container.querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])')].filter((item) => !item.hidden);
  }

  function trapFocus(container, event) {
    if (event.key !== "Tab") return;
    const items = focusable(container);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  }

  function openUnlockDialog() {
    app.previousFocus = document.activeElement;
    elements.unlockError.hidden = true;
    elements.unlockPassword.value = "";
    elements.unlockLayer.hidden = false;
    syncOverlayState();
    window.setTimeout(() => elements.unlockPassword.focus(), 0);
  }

  function closeUnlockDialog() {
    elements.unlockLayer.hidden = true;
    elements.unlockPassword.value = "";
    syncOverlayState();
    app.previousFocus?.focus?.();
  }

  async function unlockSession(event) {
    event.preventDefault();
    const submit = elements.unlockForm.querySelector('button[type="submit"]');
    setBusy(submit, true, "验证中");
    try {
      const payload = await api("/api/auth/unlock", { method: "POST", body: { password: elements.unlockPassword.value } });
      const updated = sessionPayload(payload);
      app.session = {
        ...app.session,
        ...updated,
        authenticated: true,
        csrfToken: updated.csrfToken || app.session.csrfToken,
        user: updated.user || app.session.user
      };
      if (!app.session.unlockedUntil) app.session.unlockedUntil = Date.now() + 15 * 60_000;
      renderSession();
      closeUnlockDialog();
      toast("配置操作已解锁 15 分钟", "success");
    } catch (error) {
      elements.unlockError.textContent = error.message;
      elements.unlockError.hidden = false;
      elements.unlockPassword.select();
    } finally {
      setBusy(submit, false, "验证中");
    }
  }

  function stopTimers() {
    clearInterval(app.refreshTimer); clearInterval(app.lockTimer);
    app.refreshTimer = null; app.lockTimer = null;
    app.refreshController?.abort();
  }

  function scheduleTimers() {
    clearInterval(app.refreshTimer);
    const interval = Number(elements.refreshInterval.value);
    if (interval > 0) {
      app.refreshTimer = window.setInterval(() => {
        if (!document.hidden && !app.refreshPromise) refreshAll({ silent: true });
      }, interval);
    }
    clearInterval(app.lockTimer);
    app.lockTimer = window.setInterval(renderSession, 30_000);
  }

  async function bootstrap() {
    applyTheme(localStorage.getItem("arista-theme") || "dark");
    const savedInterval = localStorage.getItem("arista-refresh");
    if (savedInterval && [...elements.refreshInterval.options].some((option) => option.value === savedInterval)) elements.refreshInterval.value = savedInterval;
    elements.diagnosticCommand.innerHTML = DIAGNOSTICS.map(([value, label, description]) => `<option value="${value}">${escapeHtml(label)} — ${escapeHtml(description)}</option>`).join("");
    elements.changeAction.innerHTML = Object.entries(CHANGE_ACTIONS).map(([value, definition]) => `<option value="${value}">${escapeHtml(definition.label)}</option>`).join("");
    renderDiagnosticFields(); renderChangeFields();
    try {
      const payload = await api("/api/auth/session");
      app.session = sessionPayload(payload);
      if (!app.session.authenticated) return showLogin();
      showApp();
      await refreshAll({ silent: true });
    } catch (error) {
      if (error.status !== 401) showLogin(`无法读取会话：${error.message}`);
      else showLogin();
    }
  }

  function applyTheme(theme) {
    const next = theme === "light" ? "light" : "dark";
    document.body.dataset.theme = next;
    localStorage.setItem("arista-theme", next);
    elements.themeButton.setAttribute("aria-label", `切换为${next === "dark" ? "浅色" : "深色"}主题`);
    requestAnimationFrame(drawTrafficChart);
  }

  elements.loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = elements.loginForm.querySelector('button[type="submit"]');
    setBusy(submit, true, "登录中");
    elements.loginError.hidden = true;
    try {
      const payload = await api("/api/auth/login", { method: "POST", body: { username: elements.loginUsername.value.trim(), password: elements.loginPassword.value } });
      app.session = sessionPayload(payload);
      if (!app.session.authenticated) throw new Error("服务端未建立登录会话。");
      elements.loginPassword.value = "";
      showApp();
      await refreshAll({ silent: true });
    } catch (error) {
      elements.loginError.textContent = error.message;
      elements.loginError.hidden = false;
      elements.loginPassword.value = "";
      elements.loginPassword.focus();
    } finally {
      setBusy(submit, false, "登录中");
    }
  });

  document.querySelector(".primary-nav").addEventListener("click", (event) => {
    const link = event.target.closest("a[data-route]");
    if (!link) return;
    event.preventDefault(); routeTo(link.pathname);
  });
  window.addEventListener("popstate", () => routeTo(location.pathname, false));
  elements.refreshButton.addEventListener("click", () => refreshAll());
  elements.refreshInterval.addEventListener("change", () => { localStorage.setItem("arista-refresh", elements.refreshInterval.value); scheduleTimers(); });
  elements.themeButton.addEventListener("click", () => applyTheme(document.body.dataset.theme === "dark" ? "light" : "dark"));
  elements.logoutButton.addEventListener("click", async () => {
    elements.logoutButton.disabled = true;
    elements.logoutButton.setAttribute("aria-busy", "true");
    try {
      await api("/api/auth/logout", { method: "POST", body: {} });
      showLogin();
    } catch (error) {
      if (error.code === "authentication_required") showLogin();
      else toast(`退出失败：${error.message}`, "error");
    } finally {
      elements.logoutButton.disabled = false;
      elements.logoutButton.setAttribute("aria-busy", "false");
    }
  });
  elements.unlockButton.addEventListener("click", openUnlockDialog);
  elements.portSearch.addEventListener("input", renderPorts);
  elements.portFilter.addEventListener("change", renderPorts);
  elements.portGrid.addEventListener("click", (event) => openPortDrawer(app.portByKey.get(event.target.closest("[data-port-key]")?.dataset.portKey)));
  elements.drawerClose.addEventListener("click", closePortDrawer);
  elements.drawerBackdrop.addEventListener("click", closePortDrawer);
  elements.diagnosticCommand.addEventListener("change", renderDiagnosticFields);
  elements.diagnosticForm.addEventListener("submit", runDiagnostic);
  elements.copyDiagnostic.addEventListener("click", async () => { await navigator.clipboard.writeText(elements.diagnosticOutput.textContent); toast("诊断输出已复制", "success"); });
  elements.changeAction.addEventListener("change", renderChangeFields);
  elements.changeForm.addEventListener("input", (event) => { if (event.target !== elements.changeAction) invalidatePreview(); });
  elements.changeForm.addEventListener("change", (event) => { if (event.target !== elements.changeAction) invalidatePreview(); });
  elements.changeForm.addEventListener("submit", previewChange);
  elements.confirmApply.addEventListener("change", () => { elements.applyButton.disabled = !elements.confirmApply.checked || !app.preview; });
  elements.applyButton.addEventListener("click", applyChange);
  elements.unlockClose.addEventListener("click", closeUnlockDialog);
  elements.unlockLayer.addEventListener("click", (event) => { if (event.target === elements.unlockLayer) closeUnlockDialog(); });
  elements.unlockForm.addEventListener("submit", unlockSession);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      if (!elements.unlockLayer.hidden) closeUnlockDialog();
      else if (elements.portDrawer.classList.contains("open")) closePortDrawer();
    }
    if (!elements.unlockLayer.hidden) trapFocus(elements.unlockDialog, event);
    else if (elements.portDrawer.classList.contains("open")) trapFocus(elements.portDrawer, event);
  });
  document.addEventListener("visibilitychange", () => { if (!document.hidden && app.session.authenticated && freshnessStatus() === "stale" && !app.refreshPromise) refreshAll({ silent: true }); });
  new ResizeObserver(() => requestAnimationFrame(drawTrafficChart)).observe(elements.trafficChart);

  bootstrap();
})();
