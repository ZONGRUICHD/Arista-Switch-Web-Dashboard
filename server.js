"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");

const ROOT = __dirname;
const WEB_DIR = path.join(ROOT, "web");
const FIXTURE_FILE = path.join(ROOT, "data", "fixtures", "state.json");
const HOST = "127.0.0.1";
const PORT = parsePort(process.env.PORT || "3000");
const SESSION_TTL = 12 * 60 * 60 * 1000;
const UNLOCK_TTL = 15 * 60 * 1000;
const PREVIEW_TTL = 5 * 60 * 1000;
const BODY_LIMIT = 64 * 1024;
const ROUTES = new Set(["/", "/ports", "/network", "/diagnostics", "/changes"]);
const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml; charset=utf-8"
};
const DIAGNOSTIC_OUTPUT = {
  version: "Arista DCS-7050QX-32S-F\nHardware version: 11.00\nSoftware image version: 4.28.6.1M (fixture)\nSerial number: PREVIEW-ONLY",
  interfaces_status: "Port       Name                    Status       Vlan   Duplex Speed\nEt1/1      compute-a01             connected    10     full   10G\nEt1/4      compute-a04             connected    10     full   10G\nEt5        storage uplink          notconnect   20     full   40G",
  vlan: "VLAN  Name       Status    Ports\n1     default    active    Et4\n10    COMPUTE    active    Et1/1-4\n20    STORAGE    active    Et5",
  lldp: "Port      Neighbor Device  Neighbor Port\nEt2       spine-01         Ethernet9\nEt3       spine-02         Ethernet9",
  environment: "System temperature status is: Ok\nAll fans are Ok\nPowerSupply1 Ok\nPowerSupply2 Ok",
  routes: "VRF: default\nC  192.0.2.0/31 is directly connected, Ethernet2\nB  203.0.113.0/24 via 192.0.2.1",
  arp: "Address         Age       Hardware Addr      Interface\n192.0.2.11     0:03:12   001c.73aa.0011     Vlan10",
  mac_table: "Vlan  Mac Address       Type      Ports\n10    001c.73aa.0011    DYNAMIC   Et2\n10    5254.0091.2a01    DYNAMIC   Et1/1",
  transceivers: "Port  Type          Vendor   Temperature  Tx Power  Rx Power\nEt3   40GBASE-SR4   Finisar  43.7 C       -2.1 dBm  -2.8 dBm"
};

const sessions = new Map();
let fixtureState;

function parsePort(value) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1 || number > 65535) throw new Error("PORT must be between 1 and 65535.");
  return number;
}

function token(bytes = 24) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function nowIso() {
  return new Date().toISOString();
}

function securityHeaders(extra = {}) {
  return {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    ...extra
  };
}

function sendJson(res, status, payload, headers = {}) {
  const body = Buffer.from(JSON.stringify(payload));
  res.writeHead(status, securityHeaders({
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": String(body.length),
    ...headers
  }));
  res.end(body);
}

function sendText(res, status, body, contentType = "text/plain; charset=utf-8") {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
  res.writeHead(status, securityHeaders({ "Content-Type": contentType, "Content-Length": String(payload.length) }));
  res.end(payload);
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > BODY_LIMIT) throw apiError(413, "request_too_large", "请求体超过 64 KiB。Preview 服务已拒绝该请求。");
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw apiError(400, "invalid_json", "请求体不是有效 JSON。");
  }
}

function apiError(status, code, message) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

function cookieMap(req) {
  return Object.fromEntries(String(req.headers.cookie || "").split(";").map((item) => item.trim()).filter(Boolean).map((item) => {
    const index = item.indexOf("=");
    return index < 0 ? [item, ""] : [item.slice(0, index), decodeURIComponent(item.slice(index + 1))];
  }));
}

function currentSession(req) {
  const id = cookieMap(req).preview_session;
  const session = id ? sessions.get(id) : null;
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(id);
    return null;
  }
  return session;
}

function requireSession(req) {
  const session = currentSession(req);
  if (!session) throw apiError(401, "authentication_required", "Preview 会话未登录。");
  return session;
}

function requireCsrf(req, session) {
  const supplied = String(req.headers["x-csrf-token"] || "");
  const suppliedBytes = Buffer.from(supplied);
  const expectedBytes = Buffer.from(session.csrfToken);
  if (!supplied || suppliedBytes.length !== expectedBytes.length || !crypto.timingSafeEqual(suppliedBytes, expectedBytes)) {
    throw apiError(403, "csrf_failed", "CSRF token 无效。");
  }
}

function publicSession(session) {
  return session ? {
    authenticated: true,
    user: session.user,
    csrfToken: session.csrfToken,
    expiresAt: new Date(session.expiresAt).toISOString(),
    unlockedUntil: session.unlockedUntil ? new Date(session.unlockedUntil).toISOString() : null
  } : { authenticated: false };
}

function cloneFixture() {
  const state = structuredClone(fixtureState);
  const now = Date.now();
  const wave = Math.sin(now / 11_000);
  state.device.lastRefresh = nowIso();
  state.health.cpu = Math.round(13 + wave * 3);
  state.traffic.rxMbps = Math.round((18_540 + wave * 840) * 10) / 10;
  state.traffic.txMbps = Math.round((14_721 - wave * 620) * 10) / 10;
  const latest = state.history.traffic[state.history.traffic.length - 1];
  latest.time = state.device.lastRefresh;
  latest.rxMbps = state.traffic.rxMbps;
  latest.txMbps = state.traffic.txMbps;
  return state;
}

function diagnosticOutput(commandId, target) {
  if (commandId === "ping") return `PING ${target} (fixture)\n64 bytes from ${target}: icmp_seq=1 ttl=64 time=0.428 ms\n64 bytes from ${target}: icmp_seq=2 ttl=64 time=0.391 ms\n\n2 packets transmitted, 2 received, 0% packet loss`;
  if (commandId === "traceroute") return `traceroute to ${target} (fixture), 8 hops max\n 1  192.0.2.1  0.421 ms  0.407 ms  0.395 ms\n 2  ${target}  0.817 ms  0.803 ms  0.798 ms`;
  return DIAGNOSTIC_OUTPUT[commandId];
}

function validateTarget(value) {
  const target = String(value || "").trim();
  if (!target || target.length > 253 || !/^[A-Za-z0-9:._-]+$/.test(target)) throw apiError(400, "invalid_target", "目标只允许 IP 地址或安全主机名字符。");
  return target;
}

function previewCommands(action, params) {
  const item = (name, fallback = "<required>") => String(params?.[name] || fallback);
  const commands = {
    interface_admin: [`interface ${item("interface")}`, item("state") === "disable" ? "shutdown" : "no shutdown"],
    poe_control: [`interface ${item("interface")}`, item("state") === "disable" ? "poe disable" : "poe enable"],
    description: [`interface ${item("interface")}`, `description ${item("description")}`],
    access_vlan: [`interface ${item("interface")}`, "switchport mode access", `switchport access vlan ${item("vlan")}`],
    trunk_vlan: [`interface ${item("interface")}`, "switchport mode trunk", `switchport trunk allowed vlan ${item("vlan")}`, ...(params?.nativeVlan ? [`switchport trunk native vlan ${params.nativeVlan}`] : [])],
    create_vlan: [`vlan ${item("vlan")}`, ...(params?.name ? [`name ${params.name}`] : [])],
    svi_interface: [`interface Vlan${item("vlan")}`, `ip address ${item("address")}`, ...(params?.description ? [`description ${params.description}`] : [])],
    l3_interface: [`interface ${item("interface")}`, "no switchport", `ip address ${item("address")}`],
    ospf_network: [`router ospf ${item("process", "1")}`, `network ${item("network")} area ${item("area", "0")}`],
    ospf_interface: [`interface ${item("interface")}`, `ip ospf area ${item("area", "0")}`],
    bgp_neighbor: [`router bgp ${item("asn")}`, `neighbor ${item("neighbor")} remote-as ${item("remoteAs")}`],
    bgp_address_family: [`router bgp ${item("asn")}`, `address-family ${item("addressFamily", "ipv4")}`, `${item("mode", "activate") === "deactivate" ? "no " : ""}neighbor ${item("neighbor")} activate`],
    save_config: ["write memory"]
  };
  if (!commands[action]) throw apiError(400, "unsupported_action", "Preview fixture 不支持该配置操作。");
  return commands[action];
}

async function handleApi(req, res, pathname) {
  if (req.method === "GET" && pathname === "/healthz") {
    return sendJson(res, 200, { ok: true, status: "healthy", version: "fixture-preview", commit: "local" });
  }
  if (req.method === "GET" && pathname === "/api/auth/session") {
    return sendJson(res, 200, { ok: true, ...publicSession(currentSession(req)) });
  }
  if (req.method === "POST" && pathname === "/api/auth/login") {
    const body = await readBody(req);
    if (!String(body.username || "").trim() || !String(body.password || "")) throw apiError(401, "invalid_credentials", "Preview 登录需要非空用户名和密码。");
    const id = token();
    const session = { id, user: String(body.username).trim(), csrfToken: token(), expiresAt: Date.now() + SESSION_TTL, unlockedUntil: 0, previews: new Map() };
    sessions.set(id, session);
    return sendJson(res, 200, { ok: true, ...publicSession(session) }, { "Set-Cookie": `preview_session=${encodeURIComponent(id)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL / 1000}` });
  }

  const session = requireSession(req);
  if (req.method !== "GET") requireCsrf(req, session);
  if (req.method === "POST" && pathname === "/api/auth/logout") {
    sessions.delete(session.id);
    return sendJson(res, 200, { ok: true, authenticated: false }, { "Set-Cookie": "preview_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" });
  }
  if (req.method === "POST" && pathname === "/api/auth/unlock") {
    const body = await readBody(req);
    if (!String(body.password || "")) throw apiError(401, "invalid_credentials", "密码不能为空。");
    session.unlockedUntil = Date.now() + UNLOCK_TTL;
    return sendJson(res, 200, { ok: true, ...publicSession(session) });
  }
  if (req.method === "GET" && pathname === "/api/state") {
    return sendJson(res, 200, { ok: true, state: cloneFixture() });
  }
  if (req.method === "POST" && pathname === "/api/refresh") {
    const body = await readBody(req);
    if (!new Set(["core", "metrics", "health", "tables", "discovery", "optics", "protocols", "extras", "full"]).has(body.scope || "full")) throw apiError(400, "invalid_scope", "未知刷新范围。");
    await new Promise((resolve) => setTimeout(resolve, 45));
    return sendJson(res, 200, { ok: true, state: cloneFixture(), scope: body.scope || "full" });
  }
  if (req.method === "POST" && pathname === "/api/diagnostics") {
    const body = await readBody(req);
    const commandId = String(body.commandId || "");
    const target = ["ping", "traceroute"].includes(commandId) ? validateTarget(body.params?.target) : "";
    const output = diagnosticOutput(commandId, target);
    if (!output) throw apiError(400, "unknown_diagnostic", "未知诊断 ID。");
    return sendJson(res, 200, { ok: true, commandId, output });
  }
  if (req.method === "POST" && pathname === "/api/config/preview") {
    const body = await readBody(req);
    const action = String(body.action || "");
    const commands = previewCommands(action, body.params || {});
    const previewToken = token();
    const preview = { previewToken, action, commands, expiresAt: Date.now() + PREVIEW_TTL };
    session.previews.set(previewToken, preview);
    return sendJson(res, 200, {
      ok: true, previewToken, baselineHash: "fixture-baseline-001", commands,
      diff: `--- before-running-config\n+++ candidate-config\n${commands.map((command) => `+ ${command}`).join("\n")}`,
      expiresAt: new Date(preview.expiresAt).toISOString()
    });
  }
  if (req.method === "POST" && pathname === "/api/config/apply") {
    if (session.unlockedUntil <= Date.now()) throw apiError(423, "operations_locked", "配置操作尚未解锁。");
    const body = await readBody(req);
    const preview = session.previews.get(String(body.previewToken || ""));
    if (!preview || preview.expiresAt <= Date.now()) throw apiError(409, "preview_expired", "预览不存在或已过期。");
    session.previews.delete(preview.previewToken);
    return sendJson(res, 200, { ok: true, action: preview.action, commands: preview.commands, diff: "Fixture preview only — no switch configuration changed.", output: "模拟 configuration session 已提交。" });
  }
  if (req.method === "POST" && ["/api/command", "/api/config"].includes(pathname)) {
    return sendJson(res, 410, { ok: false, code: "endpoint_removed", error: "该旧接口已移除。" });
  }
  throw apiError(404, "not_found", "API 不存在。");
}

async function serveWeb(res, pathname) {
  const asset = ROUTES.has(pathname) ? "index.html" : pathname === "/app.js" ? "app.js" : pathname === "/styles.css" ? "styles.css" : null;
  if (!asset) return sendText(res, 404, "Not found");
  const body = await fs.readFile(path.join(WEB_DIR, asset));
  return sendText(res, 200, body, MIME[path.extname(asset)] || "application/octet-stream");
}

async function handleRequest(req, res) {
  const requestId = token(9);
  try {
    const url = new URL(req.url, `http://${HOST}:${PORT}`);
    if (url.pathname === "/healthz" || url.pathname.startsWith("/api/")) await handleApi(req, res, url.pathname);
    else if (req.method === "GET" || req.method === "HEAD") await serveWeb(res, url.pathname);
    else throw apiError(405, "method_not_allowed", "Method not allowed.");
  } catch (error) {
    if (res.headersSent) return res.end();
    sendJson(res, error.status || 500, { ok: false, code: error.code || "internal_error", error: error.status ? error.message : "Preview 服务发生内部错误。", requestId });
  }
}

async function main() {
  fixtureState = JSON.parse(await fs.readFile(FIXTURE_FILE, "utf8"));
  const server = http.createServer(handleRequest);
  server.listen(PORT, HOST, () => {
    console.log(`Arista dashboard fixture preview: http://${HOST}:${PORT}`);
    console.log("Preview login accepts any non-empty username and password. No remote device is contacted.");
  });
}

setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions) if (session.expiresAt <= now) sessions.delete(id);
}, 60_000).unref();

main().catch((error) => {
  console.error("Preview failed to start:", error.message);
  process.exitCode = 1;
});
