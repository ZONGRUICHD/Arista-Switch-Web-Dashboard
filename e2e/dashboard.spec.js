const { test, expect } = require("@playwright/test");

async function login(page) {
  await page.goto("/");
  const form = page.locator("#loginForm");
  await form.getByLabel("用户名").fill("preview");
  await form.getByLabel("密码").fill("preview");
  await form.getByRole("button", { name: "登录", exact: true }).click();
  await expect(page.getByRole("heading", { name: "运行概览" })).toBeVisible();
  await expect(page.locator("#overviewState")).toContainText(/数据已更新|正在加载/);
}

test("forms use explicit POST fallbacks so credentials never enter a URL", async ({ page }) => {
  await page.goto("/");
  const forms = await page.locator("form").evaluateAll((items) => items.map((form) => ({ id: form.id, method: form.method, action: form.getAttribute("action") })));
  expect(forms).toEqual([
    { id: "loginForm", method: "post", action: "/api/auth/login" },
    { id: "diagnosticForm", method: "post", action: "/api/diagnostics" },
    { id: "changeForm", method: "post", action: "/api/config/preview" },
    { id: "unlockForm", method: "post", action: "/api/auth/unlock" }
  ]);
});

test("dark/light theme and primary navigation remain usable", async ({ page }) => {
  await login(page);
  await expect(page.locator("body")).toHaveAttribute("data-theme", "dark");
  await page.getByRole("button", { name: "切换为浅色主题" }).click();
  await expect(page.locator("body")).toHaveAttribute("data-theme", "light");

  await page.getByRole("link", { name: "诊断" }).click();
  const contrast = await page.locator("#diagnosticRun").evaluate((element) => {
    const channels = (value) => value.match(/[\d.]+/g).slice(0, 3).map(Number);
    const luminance = (value) => channels(value).map((part) => part / 255).map((part) => part <= 0.04045 ? part / 12.92 : ((part + 0.055) / 1.055) ** 2.4).reduce((sum, part, index) => sum + part * [0.2126, 0.7152, 0.0722][index], 0);
    const style = getComputedStyle(element);
    const foreground = luminance(style.color);
    const background = luminance(style.backgroundColor);
    return (Math.max(foreground, background) + 0.05) / (Math.min(foreground, background) + 0.05);
  });
  expect(contrast).toBeGreaterThanOrEqual(4.5);

  await page.getByRole("link", { name: "网络" }).click();
  await expect(page).toHaveURL(/\/network$/);
  await expect(page.getByRole("heading", { name: "网络数据" })).toBeVisible();
  await expect(page.getByRole("table", { name: "LLDP 邻居" })).toBeVisible();
});

test("port filter and accessible detail drawer work", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "端口" }).click();
  await page.locator("#portFilter").selectOption("errors");
  const cards = page.locator(".port-card");
  await expect(cards).toHaveCount(2);
  await cards.first().click();
  const drawer = page.getByRole("dialog", { name: /详情/ });
  await expect(drawer).toBeVisible();
  await expect(drawer.getByText("错误计数")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.locator("#portDrawer")).toHaveAttribute("aria-hidden", "true");
  await expect(page.locator("#portDrawer")).toHaveAttribute("inert", "");
  await expect(cards.first()).toBeFocused();
  await expect(page.locator("#portDrawer")).toBeHidden();
});

test("diagnostics and preview/apply flow use fixed APIs", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "诊断" }).click();
  await page.getByLabel("诊断项目").selectOption("version");
  await page.getByRole("button", { name: "运行诊断" }).click();
  await expect(page.locator("#diagnosticOutput")).toContainText("Software image version");

  await page.getByRole("link", { name: "变更" }).click();
  const changeForm = page.locator("#changeForm");
  await changeForm.getByLabel("操作", { exact: true }).selectOption("description");
  await changeForm.getByLabel("接口", { exact: true }).fill("Ethernet4");
  await changeForm.getByLabel("描述", { exact: true }).fill("preview-link");
  await changeForm.getByRole("button", { name: "生成预览" }).click();
  await expect(page.locator("#previewOutput")).toContainText("DIFF");
  await expect(page.getByText("我已核对命令和差异")).toBeVisible();
  await page.getByRole("button", { name: "解锁操作" }).click();
  const unlock = page.getByRole("dialog", { name: "解锁配置操作" });
  await unlock.getByLabel("密码").fill("preview");
  await unlock.getByRole("button", { name: "解锁 15 分钟" }).click();
  await page.getByLabel("我已核对命令和差异").check();
  await page.getByRole("button", { name: "提交配置" }).click();
  await expect(page.locator("#previewOutput")).toContainText("Fixture preview only");
});

test("editing fields invalidates a preview and stale preview responses are ignored", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "变更" }).click();
  const form = page.locator("#changeForm");
  await form.getByLabel("操作", { exact: true }).selectOption("description");
  await form.getByLabel("接口", { exact: true }).fill("Ethernet4");
  const description = form.getByLabel("描述", { exact: true });
  await description.fill("first-preview");
  await form.getByRole("button", { name: "生成预览" }).click();
  await expect(page.locator("#previewOutput")).toContainText("first-preview");
  await page.getByLabel("我已核对命令和差异").check();
  await description.fill("edited-after-preview");
  await expect(page.locator("#applyBar")).toBeHidden();
  await expect(page.locator("#applyButton")).toBeDisabled();

  let releaseResponse;
  let markStarted;
  const started = new Promise((resolve) => { markStarted = resolve; });
  const released = new Promise((resolve) => { releaseResponse = resolve; });
  await page.route("**/api/config/preview", async (route) => {
    markStarted();
    await released;
    await route.continue();
  });
  await description.fill("in-flight-old");
  await form.getByRole("button", { name: "生成预览" }).click();
  await started;
  await description.fill("in-flight-new");
  releaseResponse();
  await expect(form.getByRole("button", { name: "生成预览" })).toBeEnabled();
  await expect(page.locator("#applyBar")).toBeHidden();
  await expect(page.locator("#previewOutput")).not.toContainText("in-flight-old");
});

test("invalid unlock credentials keep the authenticated app and dialog state", async ({ page }) => {
  await login(page);
  await page.route("**/api/auth/unlock", (route) => route.fulfill({
    status: 401,
    contentType: "application/json",
    body: JSON.stringify({ ok: false, error: { code: "invalid_credentials", message: "Invalid username or password." } })
  }));
  await page.locator("#unlockButton").click();
  await page.locator("#unlockPassword").fill("wrong");
  await page.locator("#unlockForm button[type=submit]").click();
  await expect(page.locator("#appShell")).toBeVisible();
  await expect(page.locator("#loginView")).toBeHidden();
  await expect(page.locator("#unlockLayer")).toBeVisible();
  await expect(page.locator("#unlockError")).toContainText("Invalid username or password.");
});

test("failed logout keeps the live session visible and reports the failure", async ({ page }) => {
  await login(page);
  await page.route("**/api/auth/logout", (route) => route.fulfill({
    status: 503,
    contentType: "application/json",
    body: JSON.stringify({ ok: false, error: { code: "logout_failed", message: "logout unavailable" } })
  }));
  await page.locator("#logoutButton").click();
  await expect(page.locator("#appShell")).toBeVisible();
  await expect(page.locator("#loginView")).toBeHidden();
  await expect(page.locator("#toastRegion")).toContainText("退出失败：logout unavailable");
  await expect(page.locator("#logoutButton")).toBeEnabled();
});

test("health collection failures never render a green healthy state", async ({ page }) => {
  const state = {
    device: { hostname: "health-test", model: "DCS-7050QX", lastRefresh: new Date().toISOString() },
    ports: [], alerts: [], events: [],
    loading: { core: "done", metrics: "done", health: "pending", tables: "done", discovery: "done", optics: "done", protocols: "done", extras: "done" },
    meta: { stale: false }
  };
  await page.route("**/api/refresh", async (route) => {
    const scope = route.request().postDataJSON().scope;
    if (scope === "health") {
      await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ ok: false, error: "health collection failed" }) });
      return;
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, state }) });
  });
  await login(page);
  await expect(page.locator("#overviewState")).toHaveAttribute("data-status", "error");
  await expect(page.locator("#healthLabel")).toContainText("采集失败");
  await expect(page.locator("#healthLabel")).not.toHaveClass(/safe/);
  await expect(page.locator("#healthMetrics")).toContainText("当前不可确认");
});

test("loading and refresh error states are announced", async ({ page }) => {
  let failed = false;
  await page.route("**/api/refresh", async (route) => {
    const request = route.request();
    const body = request.postDataJSON();
    if (!failed && body.scope === "metrics") {
      failed = true;
      await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ ok: false, error: "fixture collection failed" }) });
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 80));
    await route.continue();
  });
  await login(page);
  await expect(page.locator("#overviewState")).toHaveAttribute("role", "status");
  await expect(page.locator("#overviewState")).toHaveAttribute("aria-live", "polite");
  await expect(page.locator("#overviewState")).toHaveAttribute("data-status", "error");
  await expect(page.locator("#overviewState")).toContainText("部分数据加载失败");
});

test("layout has no horizontal overflow", async ({ page }) => {
  await login(page);
  for (const route of ["/", "/ports", "/network", "/diagnostics", "/changes"]) {
    await page.goto(route);
    await expect.poll(() => page.evaluate(() => ({ viewport: document.documentElement.clientWidth, page: document.documentElement.scrollWidth }))).toEqual(expect.objectContaining({ viewport: page.viewportSize().width, page: page.viewportSize().width }));
  }
  if (page.viewportSize().width <= 480) {
    for (const id of ["refreshButton", "unlockButton", "themeButton", "logoutButton"]) {
      const box = await page.locator(`#${id}`).boundingBox();
      expect(box.width).toBeGreaterThanOrEqual(44);
      expect(box.height).toBeGreaterThanOrEqual(44);
    }
  }
});
