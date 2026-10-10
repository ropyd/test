"""Browser smoke test for the front end (not part of `unittest discover`; CI runs it in its own job).

    pip install playwright && playwright install chromium
    python tests/ui_smoke.py

Starts the app on a random port with canned container data, then checks in a real browser that the pages load without
script errors, the list/packages/settings/install dialogs work, a saved theme is applied, and a phone-sized screen has no
sideways scrolling."""
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from playwright.sync_api import sync_playwright  # noqa: E402

from tests.helpers import PASSWORD, App, LimitedServer, load_config, make_handler, write_config  # noqa: E402
from tests.test_osinfo import DEBIAN_12  # noqa: E402
from udash.core import cmd_os_pending  # noqa: E402
from udash.osinfo import OS_INFO  # noqa: E402

INFO = ["UD_NAME=Debian GNU/Linux 12 (bookworm)", "UD_ID=debian", "UD_VERSION=12", "UD_CODENAME=bookworm", "UD_DEBIAN=12.9", "UD_APT=1"]


def start():
    tmp = tempfile.mkdtemp(prefix="udui-")
    extra = "services:\n  - name: debian-box\n    ctid: 501\n  - name: clean-box\n    ctid: 504\n"
    app = App(load_config(write_config(tmp, extra)), state_dir=Path(tmp) / "state", base_dir=ROOT)

    def fake_exec(uid, cmd, timeout=60, on_line=None, holder=None):
        if cmd == OS_INFO:
            return 0, INFO
        if cmd in (cmd_os_pending(True), cmd_os_pending(False)):
            return 0, DEBIAN_12 if uid == 501 else []
        return 0, []

    app.dash.runner.exec = fake_exec
    app.dash.check_all()
    c = app.catalog
    c.commit, c.core_commit, c.updated = "a" * 40, "b" * 40, time.time()
    c.entries = [{"slug": "jellyfin", "app": "Jellyfin", "tags": ["media"], "page": "https://community-scripts.org/scripts/jellyfin",
                  "cpu": 2, "ram": 2048, "disk": 8, "os": "debian", "unprivileged": True}]
    c.script_sha256 = lambda slug: ("f" * 64, 100)
    srv = LimitedServer(("127.0.0.1", 0), make_handler(app), max_connections=64)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return tmp, srv, f"http://127.0.0.1:{srv.server_address[1]}"


def launch(p):
    try:
        return p.chromium.launch()
    except Exception:                                      # no bundled browser: use an installed Chrome
        return p.chromium.launch(channel="chrome")


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)
    print("ok  ", msg)


def main():
    tmp, srv, base = start()
    errors = []
    try:
        with sync_playwright() as p:
            browser = launch(p)
            ctx = browser.new_context(viewport={"width": 1100, "height": 800})
            page = ctx.new_page()
            page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
            page.on("console", lambda m: errors.append(f"console: {m.text}") if m.type == "error" else None)
            page.on("response", lambda r: errors.append(f"HTTP {r.status} {r.url}") if r.status >= 400 and r.status != 401 else None)

            page.goto(base + "/login")
            page.fill("#username", "admin")
            page.fill("#password", PASSWORD)
            page.click("#loginBtn")
            page.wait_for_url(base + "/")
            page.wait_for_selector("#rows tr")
            check(page.locator("#rows tr").count() >= 2, "list renders rows")
            check("security" in page.inner_text("#rows"), "System pane shows security updates")
            check("12.9" in page.inner_text("#rows") and "12.10" in page.inner_text("#rows"), "point release arrow is shown")

            page.click("text=Show packages")
            page.wait_for_selector(".pkgs tbody tr")
            check(page.locator(".pkgs tbody tr").count() == 5, "package drawer lists the pending packages")
            check("libc6" in page.inner_text(".pkgs"), "package names are shown")

            page.click("#settingsBtn")
            for tab in ("appearance", "security", "hosts", "integrations", "automation", "activity", "general"):
                page.click(f"#tab-{tab}")
                check(page.locator(f"#pane-{tab}").is_visible(), f"settings tab {tab} opens")
            page.click("#tab-appearance")
            page.wait_for_selector(".preset")
            page.locator(".preset", has_text="sunset").click()
            check("gradient" in page.evaluate("getComputedStyle(document.body).backgroundImage"), "preview applies a gradient background")
            page.click("#thSave")
            page.wait_for_selector("#thMsg:text-is('Saved.')")
            page.click("#settingsClose")
            page.reload()
            page.wait_for_selector("#rows tr")
            check("gradient" in page.evaluate("getComputedStyle(document.body).backgroundImage"), "saved theme persists after reload")
            check(page.evaluate("document.documentElement.getAttribute('data-mode')") == "dark", "theme mode is applied")

            page.click("#installBtn")
            page.wait_for_selector("#catList li .btn")
            page.locator("#catList li .btn", has_text="Add").first.click()
            page.click("#planBtn")
            page.wait_for_selector("#planScript:visible")
            check("bash -c" in page.inner_text("#planScript") and "Jellyfin" in page.inner_text("#planApps"), "install plan is generated")
            page.click("#installClose")

            phone = browser.new_context(viewport={"width": 375, "height": 812}, is_mobile=True)
            m = phone.new_page()
            m.on("pageerror", lambda e: errors.append(f"pageerror(phone): {e}"))
            m.goto(base + "/login")
            m.fill("#username", "admin")
            m.fill("#password", PASSWORD)
            m.click("#loginBtn")
            m.wait_for_url(base + "/")
            m.wait_for_selector("#rows tr")
            check(m.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "phone: no sideways scrolling on the list")
            m.click("text=Show packages")
            m.wait_for_selector(".pkgs tbody tr")
            check(m.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "phone: no sideways scrolling with packages open")
            m.click("#settingsBtn")
            check(m.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "phone: settings dialog fits")
            browser.close()
    finally:
        srv.shutdown()
        shutil.rmtree(tmp, True)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        raise SystemExit("script errors in the browser")
    print("UI smoke test passed")


if __name__ == "__main__":
    main()
