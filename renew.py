#!/usr/bin/env python3
"""
NeoHeberg 自动续期 + 服务器状态检查与开机守护（GitHub Actions，单账号单代理）

流程：无头浏览器登录（两步式表单 + Cap.js）→ 读取到期日
      · 续期模式（默认）：剩余天数 <= RENEW_DAYS 则续期，随后检查容器状态，已停止则开机
      · 状态检查模式（MODE=status 或命令行 --status）：只检查容器状态，已停止则自动开机并确认，不续期

必填环境变量（在仓库 Secrets 里配置）：
  NEO_USER      账号（邮箱或用户名）
  NEO_PASSWORD  密码
  NEO_VMID      服务实例 ID（纯数字）

可选环境变量：
  NEO_TYPE      服务类型，默认 vps
  RENEW_DAYS    剩余多少天时续期，默认 14
  FORCE_RENEW   设为 true 则忽略剩余天数，强制续期
  MODE          设为 status 进入状态检查模式
  START_WAIT    下发开机指令后最多等多少秒确认容器运行起来，默认 90
  LOGIN_ATTEMPTS 登录失败时最多尝试几次，默认 3（账号密码错误或被 Cloudflare 拦截时不重试）
  PROXY_SERVER  代理地址，如 socks5://127.0.0.1:1080 或 http://user:pass@host:port
                （workflow 里配置 NODE_LINK / PROXY_SERVER 时由 setup_proxy.py 准备）

代理规则（不可用的代理绝不会悄悄改成直连）：
  · 配置了代理：先确认它可用；不可用（或 NODE_LINK 启动失败）则本次取消
  · 没有配置代理：直连

Telegram 推送（可选）：
  TG_BOT_TOKEN  机器人 Token（@BotFather 创建）
  TG_CHAT_ID    接收消息的 Chat ID
  TG_NOTIFY     always(默认,每次都发) / change(续期或自动开机或失败才发) / fail(仅失败才发)
"""
import html
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse, unquote
from urllib.request import Request, urlopen
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

BASE = "https://dash.neoheberg.fr"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

USER = os.environ.get("NEO_USER", "").strip()
PASSWORD = os.environ.get("NEO_PASSWORD", "").strip()
VMID = os.environ.get("NEO_VMID", "").strip()
TYPE = (os.environ.get("NEO_TYPE") or "vps").strip()
RENEW_DAYS = int(os.environ.get("RENEW_DAYS") or 14)
FORCE_RENEW = os.environ.get("FORCE_RENEW", "").lower() in ("1", "true", "yes")
STATUS_ONLY = os.environ.get("MODE", "").strip().lower() == "status" or "--status" in sys.argv
START_WAIT = int(os.environ.get("START_WAIT") or 90)
ATTEMPTS = int(os.environ.get("LOGIN_ATTEMPTS") or 3)
BACKOFF = [15, 60, 180]  # 登录失败后的等待秒数（站点有 429 速率限制）

# 代理（单个，取第一个非空非注释行）
PROXY = next((ln.strip() for ln in os.environ.get("PROXY_SERVER", "").replace("\r", "").split("\n")
              if ln.strip() and not ln.strip().startswith("#")), "")
# setup_proxy.py 在 NODE_LINK 启动失败时写入；表示"配置了代理但它不可用"
PROXY_FAILED = (os.environ.get("PROXY_FAILED") or os.environ.get("GLOBAL_PROXY_FAILED") or "").lower() in ("1", "true", "yes")

TG_TOKEN = os.environ.get("TG_BOT_TOKEN", "").strip()
TG_CHAT = os.environ.get("TG_CHAT_ID", "").strip()
TG_NOTIFY = (os.environ.get("TG_NOTIFY", "") or "always").strip().lower()  # always / change / fail
TG_ACCOUNT_LABEL = os.environ.get("TG_ACCOUNT_LABEL", "").strip()

ACC = {"user": USER, "password": PASSWORD, "vmid": VMID, "type": TYPE}  # 供下面的面板函数使用


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def snap(page, name):
    """失败时保存截图 + HTML，供 Actions artifacts 下载排查。"""
    try:
        page.screenshot(path=f"{name}.png", full_page=True)
        with open(f"{name}.html", "w", encoding="utf-8") as f:
            f.write(page.content())
    except Exception:
        pass


# ───────────────────────── 登录 ─────────────────────────
BLOCKED = "blocked"      # 被 Cloudflare 托管质询拦截
BADCREDS = "badcreds"    # 站点提示账号或密码无效
FAILED = "failed"        # 其他失败


def mask(s, show=2):
    s = str(s)
    return s if len(s) <= show * 2 else s[:show] + "*" * (len(s) - show * 2) + s[-show:]


def read_csrf(page):
    try:
        return page.evaluate("""() => {
            const i = document.querySelector('input[name="csrf_token"]');
            if (i && i.value) return i.value;
            const m = document.querySelector('meta[name="csrf-token"]');
            if (m && m.content) return m.content;
            if (typeof window.CSRF === 'string') return window.CSRF;
            return '';
        }""") or ""
    except Exception:
        return ""


def cf_blocked(page):
    """当前页面是否是 Cloudflare 质询页（注意：正常页面也会带 challenge-platform 脚本，不能只看它）。"""
    try:
        title = page.title()
        html = page.content()
    except Exception:
        return False
    return title.startswith(("Un instant", "Just a moment", "Attention Required")) or "_cf_chl_opt" in html


def wait_cf_clear(page, timeout=25):
    """遇到质询页先等一会儿（非交互式质询会自动通过）；仍未通过则返回 False。"""
    if not cf_blocked(page):
        return True
    log("检测到 Cloudflare 质询页，等待自动通过 …")
    end = time.time() + timeout
    while time.time() < end:
        page.wait_for_timeout(2000)
        if not cf_blocked(page):
            log("质询已通过")
            return True
    snap(page, "cloudflare_challenge")
    return False


def login_once(page, ctx, user, password):
    """返回 True / BLOCKED / BADCREDS / FAILED。"""
    page.goto(BASE + "/login", wait_until="domcontentloaded", timeout=60000)
    if not wait_cf_clear(page):
        return BLOCKED

    # 第一步：账号
    try:
        page.wait_for_selector('input[name="identifier"]', timeout=45000)
    except PWTimeout:
        if cf_blocked(page):
            snap(page, "cloudflare_challenge")
            return BLOCKED
        log("登录表单未渲染（站点可能返回了残缺页面）")
        snap(page, "login_no_form")
        return FAILED
    page.fill('input[name="identifier"]', user)
    page.click("#goToPassword")

    # 第二步：密码框出现
    try:
        page.wait_for_selector('input[name="password"]', timeout=25000)
    except PWTimeout:
        log("密码框未出现")
        snap(page, "login_no_password")
        return FAILED

    # Cap.js 验证码：触发求解，轮询 cap-token（约 10~20 秒）
    page.evaluate("() => { const w = document.getElementById('cap-login'); if (w && w.solve) w.solve(); }")
    token = ""
    for _ in range(30):
        page.wait_for_timeout(2000)
        token = page.evaluate(
            "() => { const e = document.querySelector('input[name=\"cap-token\"]');"
            " return e ? e.value : ''; }")
        if token and len(token) > 20:
            break
    if not token:
        log("验证码求解超时")
        snap(page, "login_cap_timeout")
        return FAILED
    log("验证码通过")

    page.fill('input[name="password"]', password)
    csrf = read_csrf(page)
    page.evaluate("""(csrf) => {
        const f = document.querySelector('input[name="password"]').form;
        if (csrf && !f.querySelector('input[name="csrf_token"]')) {
            const h = document.createElement('input');
            h.type = 'hidden'; h.name = 'csrf_token'; h.value = csrf;
            f.appendChild(h);
        }
        f.submit();
    }""", csrf)

    try:
        page.wait_for_url(re.compile(r"dash\.neoheberg\.fr/(\?.*)?$"), timeout=45000)
    except PWTimeout:
        pass
    page.wait_for_timeout(2000)

    names = {c["name"] for c in ctx.cookies()}
    if "__Host-NH-Remember" in names or "/login" not in page.url:
        return True
    if cf_blocked(page):
        log("提交登录后被 Cloudflare 质询拦截")
        snap(page, "cloudflare_challenge")
        return BLOCKED
    try:
        err = page.evaluate("""() => { const a = document.querySelector('[role=alert], .alert-card');
                                       return a ? a.innerText.trim() : ''; }""")
    except Exception:
        err = ""
    err = re.sub(r"\s+", " ", err or "")
    if err:
        log(f"站点提示: {err}")
    snap(page, "login_failed")
    if re.search(r"invalide|invalid|incorrect", err, re.I):
        return BADCREDS
    log(f"登录未成功，当前 URL: {page.url}")
    return FAILED


def login(page, ctx, user, password):
    """返回 True / BLOCKED / BADCREDS / FAILED。账号密码错误或被质询时不重试。"""
    for i in range(1, ATTEMPTS + 1):
        if i > 1:
            wait = BACKOFF[min(i - 2, len(BACKOFF) - 1)]
            log(f"第 {i}/{ATTEMPTS} 次登录尝试，等待 {wait}s …")
            time.sleep(wait)
        else:
            log(f"第 {i}/{ATTEMPTS} 次登录尝试 …")
        try:
            res = login_once(page, ctx, user, password)
        except Exception as e:
            log(f"登录异常: {type(e).__name__}: {str(e)[:150]}")
            snap(page, "login_error")
            continue
        if res is True:
            return True
        if res == BADCREDS:
            log("❌ 账号或密码被站点拒绝，已停止重试（继续重试可能触发限流或锁号）。")
            log("   请检查该账号的用户名/密码，并确认账号设置过密码（Discord 登录的账号默认没有密码）。")
            return BADCREDS
        if res == BLOCKED:
            log("❌ 被 Cloudflare 托管质询（Turnstile）拦截：当前出口 IP 信誉低，重试只会更糟，已停止。")
            log("   解决办法：配置 Secret NODE_LINK 或 PROXY_SERVER，使用干净的固定出口 IP"
                "（住宅/家宽 IP 最稳），或改用自托管 runner。")
            return BLOCKED
    return FAILED


# ───────────────────────── 面板操作（在已登录页面内 fetch，自动走同一代理与 cookie） ─────────────────────────
def ensure_origin(page):
    if not page.url.startswith(BASE):
        page.goto(BASE + "/", wait_until="domcontentloaded", timeout=60000)


def panel_fetch(page, path, form=None, ajax=False):
    ensure_origin(page)
    return page.evaluate("""async ([path, form, ajax]) => {
        const headers = {};
        if (ajax) { headers['Accept'] = 'application/json'; headers['X-Requested-With'] = 'XMLHttpRequest'; }
        const opt = { method: form ? 'POST' : 'GET', credentials: 'same-origin', headers };
        if (form) opt.body = new URLSearchParams(form);
        const r = await fetch(path, opt);
        return { status: r.status, text: await r.text() };
    }""", [path, form, ajax])


def panel_info(page):
    html = panel_fetch(page, "/")["text"]
    m = re.search(r'CSRF\s*=\s*["\']([^"\']+)', html) or \
        re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    e = re.search(r'Échéance le\s*([0-9]{2}/[0-9]{2}/[0-9]{4})', html)
    d = re.search(r'(\d+)\s*jours?\s*restants?', html)
    return (m.group(1) if m else None,
            e.group(1) if e else None,
            int(d.group(1)) if d else None)


def do_renew(page, csrf, acc):
    """提交续期请求。返回 (hint, msg)。

    hint 是站点明确给出的成败（True/False），无法判断时为 None。只有响应本身是 JSON 时才采信其中的
    success/message；如果响应是整页 HTML（续期后重定向回面板），页面脚本里的 "message" 多是无关的模板文案
    （例如 "La console de ce VPS n'a pas pu être chargée."），绝不能当成续期结果。
    """
    r = panel_fetch(page, "/services/renew", {"csrf_token": csrf, "type": acc["type"], "id": acc["vmid"]})
    hint, msg = None, ""
    try:
        d = json.loads(r["text"])
    except ValueError:
        d = None
    if isinstance(d, dict):
        msg = str(d.get("message") or d.get("error") or "")
        if isinstance(d.get("success"), bool):
            hint = d["success"]
        elif "renouvel" in msg.lower():
            hint = True
    if r["status"] >= 400:
        hint = False
    return hint, (msg or f"HTTP {r['status']}")


def parse_date(s):
    """dd/mm/yyyy（面板用的法式日期）→ date，解析失败返回 None。"""
    try:
        return datetime.strptime(s or "", "%d/%m/%Y").date()
    except ValueError:
        return None


def renewal_outcome(exp, days, exp2, days2, hint, msg):
    """判断续期是否成功，返回 (ok, 说明)。

    以面板上到期日是否真的延长为准——站点返回的提示文案不可靠（见 do_renew）。
    只有读不到到期日/剩余天数、无法比较时，才参考站点明确给出的 hint。
    """
    d1, d2 = parse_date(exp), parse_date(exp2)
    if d1 and d2:
        extended = d2 > d1
    elif days is not None and days2 is not None:
        extended = days2 > days
    else:
        extended = None

    if extended is True:
        if days is not None and days2 is not None:
            return True, f"续期成功（剩余 {days} → {days2} 天）"
        return True, f"续期成功（到期日 {exp} → {exp2}）"
    if extended is False:
        return False, f"续期未生效（到期日仍为 {exp2}）：{msg}"
    if hint is True:
        return True, "续期成功（站点已确认，但未能读取新的到期日）"
    return False, f"续期结果无法确认：{msg}"


# ───────────────────────── 容器状态检查与开机 ─────────────────────────
RUNNING_STATES = {"running", "started", "online", "on", "up"}
STOPPED_STATES = {"stopped", "halted", "shutdown", "shutoff", "off", "offline", "dead", "poweroff"}


def get_vps_status(page, acc):
    """查询容器状态，返回小写状态字符串（如 running / stopped）。失败抛异常。"""
    r = panel_fetch(page, f"/app/services/vps-stats.php?id={acc['vmid']}", ajax=True)
    if r["status"] >= 400:
        raise RuntimeError(f"HTTP {r['status']}")
    st = json.loads(r["text"])
    if not isinstance(st, dict):
        raise ValueError("响应不是 JSON 对象")
    return str(st.get("status") or st.get("state") or "unknown").strip().lower()


def ensure_running(page, csrf, acc):
    """检查容器状态，已停止则开机并等待确认。返回 (state, detail)：

      running       本来就在运行
      started       已停止 → 已自动开机，并确认运行起来
      start_failed  已停止，开机失败（请求被拒 / 超时仍未运行）
      unknown       状态不在已知的"运行/停止"范围内（如 paused），不自动处理
      error         查询状态本身失败（接口变了/网络问题）
    """
    try:
        status = get_vps_status(page, acc)
    except Exception as e:
        log(f"⚠️ 查询容器状态失败: {type(e).__name__}: {str(e)[:100]}")
        return "error", f"{type(e).__name__}"
    log(f"容器状态: {status}")
    if status in RUNNING_STATES:
        return "running", status
    if status not in STOPPED_STATES:
        log(f"⚠️ 容器状态「{status}」不是已知的运行/停止状态，不自动处理")
        return "unknown", status

    log("⚠️ 容器已停止，正在开机 …")
    try:
        r = panel_fetch(page, "/app/services/vps-power.php",
                        {"vmid": acc["vmid"], "signal": "start", "csrf_token": csrf}, ajax=True)
    except Exception as e:
        log(f"❌ 开机请求异常: {type(e).__name__}: {str(e)[:100]}")
        return "start_failed", f"请求异常 {type(e).__name__}"
    if r["status"] >= 400:
        log(f"❌ 开机请求被拒绝: HTTP {r['status']}")
        return "start_failed", f"开机请求 HTTP {r['status']}"
    log(f"已下发开机指令: HTTP {r['status']}，等待容器启动 …")

    last = status
    for _ in range(max(1, START_WAIT // 5)):
        page.wait_for_timeout(5000)
        try:
            last = get_vps_status(page, acc)
        except Exception:
            continue
        if last in RUNNING_STATES:
            log(f"✅ 容器已启动（状态: {last}）")
            return "started", last
    log(f"❌ 开机指令已下发，但 {START_WAIT} 秒内状态仍为 {last}")
    return "start_failed", f"{START_WAIT} 秒内状态仍为 {last}"


def vm_note(state, detail):
    """续期流程里附加在结果后的容器状态说明，返回 (后缀, 是否致命)。"""
    return {
        "running": ("", False),
        "started": ("；容器已停止，已自动开机", False),
        "start_failed": (f"；容器开机失败（{detail}）", True),
        "unknown": (f"；容器状态异常（{detail}，未自动处理）", False),
        "error": ("；容器状态检查失败", False),
    }[state]


def status_outcome(state, detail, days):
    """状态检查模式下的结果，返回 (status, 说明)。"""
    if state == "running":
        return "ok", f"运行中（剩余 {days} 天）" if days is not None else "运行中"
    if state == "started":
        return "started", "容器已停止，已自动开机"
    if state == "start_failed":
        return "failed", f"容器已停止，开机失败（{detail}）"
    if state == "unknown":
        return "failed", f"容器状态异常：{detail}（未自动处理）"
    return "failed", f"无法获取容器状态（{detail}）"


# ───────────────────────── 代理 ─────────────────────────
def build_proxy(url):
    """代理 URL -> Playwright proxy 参数。支持 http/https/socks5，可带账号密码。"""
    if not url:
        return None
    u = urlparse(url)
    scheme = {"socks5h": "socks5"}.get(u.scheme, u.scheme)
    if scheme not in ("http", "https", "socks5", "socks4") or not u.hostname or not u.port:
        raise ValueError("代理格式应为 scheme://[user:pass@]host:port（http/https/socks5）")
    host = f"[{u.hostname}]" if ":" in u.hostname else u.hostname
    proxy = {"server": f"{scheme}://{host}:{u.port}"}
    if u.username:
        if scheme.startswith("socks"):
            log("⚠️ Chromium 不支持带账号密码的 SOCKS5，请改用 NODE_LINK（sing-box）或 HTTP 代理")
        proxy["username"] = unquote(u.username)
        proxy["password"] = unquote(u.password or "")
    return proxy


def check_proxy(p, url):
    """经该代理访问 ipify。成功返回出口 IP，失败返回 None（偶发抖动重试一次）。"""
    try:
        pr = build_proxy(url)
    except ValueError as e:
        log(f"⚠️ {e}")
        return None
    for attempt in (1, 2):
        browser = None
        try:
            browser = p.chromium.launch(headless=True, proxy=pr,
                                        args=["--no-sandbox", "--disable-dev-shm-usage"])
            page = browser.new_page()
            page.goto("https://api.ipify.org", timeout=20000)
            text = page.inner_text("body").strip()
            if re.fullmatch(r"[0-9a-fA-F:.]{7,45}", text):
                return text
        except Exception:
            pass
        finally:
            if browser:
                browser.close()
        if attempt == 1:
            time.sleep(3)
    return None


# ───────────────────────── Telegram 推送 ─────────────────────────
def tg_send(text):
    """发送 Telegram 消息。任何失败都只记录日志，绝不影响续期结果（也不会把 token 打到日志里）。"""
    if not (TG_TOKEN and TG_CHAT):
        return False
    try:
        data = urlencode({"chat_id": TG_CHAT, "text": text[:3900], "parse_mode": "HTML",
                          "disable_web_page_preview": "true"}).encode()
        req = Request(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage", data=data)
        with urlopen(req, timeout=20) as r:
            ok = r.status == 200
        log("📨 Telegram 推送成功" if ok else "⚠️ Telegram 推送失败")
        return ok
    except HTTPError as e:
        hint = {401: "（Bot Token 无效）", 400: "（Chat ID 无效，或还没给机器人发过消息）",
                403: "（机器人被拉黑或无权限）"}.get(e.code, "")
        log(f"⚠️ Telegram 推送失败: HTTP {e.code}{hint}")
    except Exception as e:
        log(f"⚠️ Telegram 推送失败: {type(e).__name__}")
    return False


def should_notify(status):
    return {"always": True, "fail": status == "failed", "change": status != "ok"}.get(TG_NOTIFY, True)


def build_report(status, note, title="NeoHeberg 续期报告"):
    bj = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M")
        header = html.escape(TG_ACCOUNT_LABEL) if TG_ACCOUNT_LABEL else f"账号：{html.escape(USER)}"
      icon = {"renewed": "✅", "ok": "✔️", "started": "🔄", "failed": "❌"}[status]
lines = [header, f"<b>{html.escape(title)}</b>", f"🕐 {bj} (北京时间)", "", f"{icon} {html.escape(note)}"]
    repo, run = os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GITHUB_RUN_ID")
    if repo and run:
        server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
        lines += ["", f'<a href="{server}/{repo}/actions/runs/{run}">查看运行日志</a>']
    return "\n".join(lines)


# ───────────────────────── 主流程 ─────────────────────────
def run(p):
    """执行一次任务，返回 (status, note)。status: renewed / ok / started / failed。"""
    # ── 代理：配置了就必须可用，绝不悄悄直连 ──
    if PROXY:
        ip = check_proxy(p, PROXY)
        if not ip:
            log("❌ 代理不可用，本次取消（不会直连）")
            return "failed", "代理不可用，已取消（不会直连）"
        host = urlparse(PROXY).hostname or ""
        log(f"使用代理: {urlparse(PROXY).scheme}://{mask(host, 3)}，出口 IP: {mask(ip, 3)}")
    elif PROXY_FAILED:
        log("❌ 配置了代理（NODE_LINK）但启动失败，本次取消（不会直连）")
        return "failed", "代理启动失败，已取消（不会直连）"

    kw = dict(headless=True, args=["--disable-blink-features=AutomationControlled",
                                   "--no-sandbox", "--disable-dev-shm-usage"])
    if PROXY:
        kw["proxy"] = build_proxy(PROXY)

    browser = p.chromium.launch(**kw)
    try:
        ctx = browser.new_context(user_agent=UA, locale="fr-FR", viewport={"width": 1920, "height": 1080})
        page = ctx.new_page()
        page.set_default_timeout(30000)
        try:
            res = login(page, ctx, USER, PASSWORD)
            if res is not True:
                return "failed", {BLOCKED: "被 Cloudflare 拦截", BADCREDS: "账号或密码错误"}.get(res, "登录失败")
            log("✅ 登录成功")

            csrf, exp, days = panel_info(page)
            log(f"到期日: {exp}  剩余: {days} 天")
            if not csrf:
                log("❌ 未取到 CSRF token")
                snap(page, "no_csrf")
                return "failed", "未取到 CSRF token"

            if STATUS_ONLY:  # 状态检查模式：只检查容器、停止则开机，不续期
                state, detail = ensure_running(page, csrf, ACC)
                return status_outcome(state, detail, days)

            if FORCE_RENEW or days is None or days <= RENEW_DAYS:
                if FORCE_RENEW:
                    log("已指定强制续期")
                hint, msg = do_renew(page, csrf, ACC)
                _, exp2, days2 = panel_info(page)
                log(f"续期后到期日: {exp2}  剩余: {days2} 天")
                ok, note = renewal_outcome(exp, days, exp2, days2, hint, msg)
                log(("✅ " if ok else "❌ ") + note)
                state, detail = ensure_running(page, csrf, ACC)
                suffix, fatal = vm_note(state, detail)
                return ("renewed" if ok and not fatal else "failed"), note + suffix

            log(f"剩余天数 > {RENEW_DAYS}，本次无需续期")
            state, detail = ensure_running(page, csrf, ACC)
            suffix, fatal = vm_note(state, detail)
            status = "failed" if fatal else ("started" if state == "started" else "ok")
            return status, f"无需续期（剩余 {days} 天）" + suffix
        except Exception as e:
            log(f"❌ 处理异常: {type(e).__name__}: {str(e)[:150]}")
            snap(page, "error")
            return "failed", f"异常: {type(e).__name__}"
    finally:
        browser.close()


def main():
    for secret in (TG_TOKEN, TG_CHAT):  # 让 Actions 日志屏蔽 TG 凭据
        if secret:
            print(f"::add-mask::{secret}", flush=True)

    title = "NeoHeberg 状态检查" if STATUS_ONLY else "NeoHeberg 续期报告"
    missing = [n for n, v in (("NEO_USER", USER), ("NEO_PASSWORD", PASSWORD), ("NEO_VMID", VMID)) if not v]
    if missing:
        log(f"❌ 缺少配置: {', '.join(missing)}（请在仓库 Secrets 里设置 NEO_USER / NEO_PASSWORD / NEO_VMID）")
        tg_send(f"❌ <b>{html.escape(title)}</b>：缺少配置 {html.escape(', '.join(missing))}")
        return 1

    for v in (USER, PASSWORD):  # 让 Actions 日志屏蔽账号和密码（防止公开仓库泄露）
        if len(v) >= 4 and "\n" not in v:
            print(f"::add-mask::{v}", flush=True)

    log(("状态检查模式：只检查容器状态，已停止则自动开机，不续期" if STATUS_ONLY
         else f"续期模式：续期阈值 {RENEW_DAYS} 天" + ("，强制续期" if FORCE_RENEW else "")))
    log(f"账号={mask(USER)}（{len(USER)}位） 密码={len(PASSWORD)}位 实例={mask(VMID)}")

    with sync_playwright() as p:
        status, note = run(p)

    icon = {"renewed": "✅", "ok": "✔️", "started": "🔄", "failed": "❌"}[status]
    log("═════════ 结果 ═════════")
    log(f"{icon} {note}")
    if should_notify(status):
        tg_send(build_report(status, note, title))
    return 1 if status == "failed" else 0


if __name__ == "__main__":
    sys.exit(main())
