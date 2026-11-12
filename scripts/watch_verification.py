"""Open the current Actions WeChat QR directly in the computer's browser.

Run this on the user's computer, not on the GitHub runner. It reads only the
selected repository's run and artifact APIs. Credentials stay in this process;
the browser receives only status and the current QR image over localhost.
Python's standard library plus Git/curl (already installed with Git for Windows)
are sufficient. No school credentials or additional third-party server is used.
"""

import argparse
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import json
import os
from pathlib import PurePosixPath
import re
import secrets
import shutil
import subprocess
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler
import webbrowser
import zipfile


class GitHubError(RuntimeError):
    pass


def load_token():
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    environment = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="Never")
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
    try:
        result = subprocess.run(
            ["git", "credential", "fill"], input="protocol=https\nhost=github.com\n\n",
            text=True, encoding="utf-8", capture_output=True, timeout=30, env=environment, **options,
        )
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if result.returncode == 0 and values.get("password"):
            return values["password"]
    except (OSError, subprocess.TimeoutExpired):
        pass
    raise GitHubError("请先在本机完成 GitHub 登录：git credential-manager github login --device")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHubClient:
    def __init__(self, repository, token):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("Invalid repository name")
        if not re.fullmatch(r"[A-Za-z0-9_]+", token):
            raise GitHubError("GitHub 登录凭据格式无效，请重新登录。")
        self.base = f"https://api.github.com/repos/{repository}"
        self.token = token

    def get(self, endpoint, *, binary=False):
        if not re.fullmatch(r"/[A-Za-z0-9_./?=&%-]+", endpoint) or ".." in endpoint:
            raise ValueError("Invalid API endpoint")
        url = self.base + endpoint
        if shutil.which("curl.exe" if os.name == "nt" else "curl"):
            # curl deliberately drops Authorization on redirects to a different
            # hostname. The artifact's signed storage URL stays out of logs.
            settings = (
                'silent\nshow-error\nlocation\nconnect-timeout = 5\nmax-time = 12\n'
                f'url = "{url}"\n'
                'header = "Accept: application/vnd.github+json"\n'
                'header = "X-GitHub-Api-Version: 2022-11-28"\n'
                'header = "User-Agent: iCourse-Local-Verification"\n'
                f'header = "Authorization: Bearer {self.token}"\n'
                'write-out = "\\n%{http_code}"\n'
            )
            options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
            try:
                result = subprocess.run(
                    ["curl.exe" if os.name == "nt" else "curl", "--config", "-"],
                    input=settings.encode(), capture_output=True, timeout=15, **options,
                )
            except (OSError, subprocess.TimeoutExpired):
                raise GitHubError("连接 GitHub 暂时失败，正在重试。") from None
            if result.returncode:
                raise GitHubError("连接 GitHub 暂时失败，正在重试。")
            raw, status = result.stdout.rsplit(b"\n", 1)
            code = int(status)
        else:
            request = Request(url, headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json", "User-Agent": "iCourse-Local-Verification",
            })
            try:
                with build_opener(NoRedirect).open(request, timeout=12) as response:
                    raw, code = response.read(4 * 1024 * 1024), response.status
            except HTTPError as exc:
                if exc.code in (301, 302, 303, 307, 308) and binary:
                    location = exc.headers.get("Location", "")
                    if not location.startswith("https://"):
                        raise GitHubError("二维码下载地址无效。") from None
                    try:
                        with build_opener().open(location, timeout=12) as response:
                            raw, code = response.read(4 * 1024 * 1024), response.status
                    except (OSError, HTTPError):
                        raise GitHubError("二维码刷新中，正在重试。") from None
                else:
                    code, raw = exc.code, b""
            except (OSError, URLError):
                raise GitHubError("连接 GitHub 暂时失败，正在重试。") from None
        if code == 404:
            raise GitHubError("暂未找到二维码，可能正在刷新；请确认当前账号有仓库 Actions 读取权限。")
        if code in (401, 403):
            raise GitHubError("GitHub 登录已过期或没有 Actions 读取权限，请重新登录。")
        if code != 200:
            raise GitHubError(f"GitHub 返回 HTTP {code}，正在重试。")
        if len(raw) > 4 * 1024 * 1024:
            raise GitHubError("二维码响应过大。")
        return raw if binary else json.loads(raw)


def select_run(runs, pinned_run=None):
    eligible = [run for run in runs if PurePosixPath(run.get("path", "").split("@")[0]).name
                in ("check.yml", "single_run.yml")]
    if pinned_run is not None:
        return next((run for run in eligible if run["id"] == pinned_run), None)
    eligible.sort(key=lambda run: run.get("created_at", ""), reverse=True)
    return next((run for run in eligible if run["status"] != "completed"), eligible[0] if eligible else None)


def select_artifact(artifacts, run):
    prefix = f"wechat-verification-{run['id']}-{run.get('run_attempt', 1)}-wechat-"
    valid = [item for item in artifacts if item.get("name", "").startswith(prefix)
             and not item.get("expired") and 0 < item.get("size_in_bytes", 0) < 4 * 1024 * 1024]
    return max(valid, key=lambda item: (item.get("created_at", ""), item["id"]), default=None)


def qr_from_archive(archive):
    """Read only a small raster image; never execute downloaded HTML or JS."""
    try:
        with zipfile.ZipFile(BytesIO(archive)) as bundle:
            for item in bundle.infolist():
                if not re.fullmatch(r"wechat-[a-f0-9]{32}\.(png|jpeg|gif)", item.filename):
                    continue
                if item.file_size > 2 * 1024 * 1024:
                    raise GitHubError("二维码图片过大。")
                raw = bundle.read(item)
                if raw.startswith(b"\x89PNG\r\n\x1a\n"):
                    mime = "image/png"
                elif raw.startswith(b"\xff\xd8\xff"):
                    mime = "image/jpeg"
                elif raw.startswith((b"GIF87a", b"GIF89a")):
                    mime = "image/gif"
                else:
                    raise GitHubError("二维码图片格式无效。")
                return f"data:{mime};base64," + base64.b64encode(raw).decode()
    except (zipfile.BadZipFile, OSError):
        raise GitHubError("二维码下载不完整，正在重试。") from None
    raise GitHubError("附件中没有找到二维码图片。")


class Watcher:
    def __init__(self, client, repository, *, run_id=None, opener=None):
        self.client = client
        self.repository = repository
        self.run_id = run_id
        self.opener = opener or (lambda: None)
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.state = {"phase": "waiting", "title": "正在连接 GitHub", "detail": "无需下载或解压文件，二维码出现后会自动显示。", "image": ""}
        self.cached = None
        self.opened_runs = set()

    def update(self, **values):
        with self.lock:
            self.state.update(values)

    def snapshot(self):
        with self.lock:
            return dict(self.state)

    def tick(self):
        if self.run_id is not None:
            run = self.client.get(f"/actions/runs/{self.run_id}")
        else:
            runs = self.client.get("/actions/runs?per_page=12")["workflow_runs"]
            run = select_run(runs)
        if not run:
            self.update(phase="waiting", title="等待新的课程任务", detail="请从 main 分支发起 iCourse Check；出现二维码时浏览器会自动显示。", image="")
            return
        run_id = run["id"]
        self.update(run_number=run.get("run_number"), run_id=run_id,
                    run_url=f"https://github.com/{self.repository}/actions/runs/{run_id}")
        if run["status"] == "completed":
            self.cached = None
            success = run.get("conclusion") == "success"
            self.update(phase="success" if success else "ended", image="",
                        title="课程任务已完成" if success else "本轮任务已结束",
                        detail="助手会继续等待下一轮。" if success else "这一轮的二维码已失效。请从 main 分支开始新一轮，助手会自动显示新的扫码页面。")
            return
        items = self.client.get(f"/actions/runs/{run_id}/artifacts?per_page=100")["artifacts"]
        artifact = select_artifact(items, run)
        if not artifact:
            self.cached = None
            self.update(phase="waiting", title="正在等待扫码或继续处理课程", image="",
                        detail="任务可能正在登录、刷新二维码或已确认通过。需要扫码时会自动显示，请保持助手运行。")
            return
        key = (run_id, run.get("run_attempt", 1), artifact["id"])
        if self.cached != key:
            archive = self.client.get(f"/actions/artifacts/{artifact['id']}/zip", binary=True)
            image = qr_from_archive(archive)
            self.cached = key
            self.update(phase="scan", title="请使用微信扫码确认", image=image,
                        detail="请用绑定学校账号的微信扫描下方二维码并确认。二维码会自动刷新，确认后云端任务继续。")
            if (run_id, run.get("run_attempt", 1)) not in self.opened_runs:
                self.opened_runs.add((run_id, run.get("run_attempt", 1)))
                try:
                    self.opener()
                except (OSError, webbrowser.Error):
                    pass

    def watch(self, interval, duration):
        deadline = time.monotonic() + duration
        while not self.stop.is_set() and time.monotonic() < deadline:
            try:
                self.tick()
            except (GitHubError, ValueError, KeyError) as exc:
                # Never retain a stale QR on transport/permissions failures.
                self.cached = None
                self.update(phase="waiting", image="", title="正在重新连接", detail=str(exc) if isinstance(exc, GitHubError) else "GitHub 响应暂不可用，正在重试。")
            self.stop.wait(interval)
        self.update(phase="ended", image="", title="扫码助手已停止", detail="需要时重新启动扫码助手。")


PAGE = """<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>iCourse 微信扫码</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f3f6fa;color:#182b43;font-family:system-ui,'Microsoft YaHei',sans-serif}
main{max-width:520px;margin:6vh auto;padding:32px;background:white;border-radius:22px;box-shadow:0 12px 50px #10294412;text-align:center}
.tag{font-size:13px;color:#537c6d;letter-spacing:2px}h1{font-size:25px;margin:18px 0 12px}p{font-size:15px;line-height:1.8;color:#596b80}
img{width:300px;max-width:100%;height:auto;image-rendering:pixelated;border:12px solid white;margin:8px auto}
#image[hidden]{display:none}a,button{font:inherit;color:#2469af}button{border:1px solid #cfdae4;background:white;border-radius:9px;padding:8px 14px;cursor:pointer}
footer{margin-top:24px;padding-top:18px;border-top:1px solid #edf1f6;font-size:13px;color:#8190a3}small{display:block;color:#8190a3;margin:16px}
</style><main><div class="tag">iCOURSE · 微信验证</div><h1 id="title">正在连接 GitHub</h1>
<p id="detail">二维码出现后会自动显示，请保持此页面打开。</p><img id="image" hidden alt="微信确认二维码">
<small id="run"></small><a id="run-link" target="_blank" rel="noreferrer" hidden>查看本轮任务</a>
<footer>扫码后请在手机上确认，原任务会自动继续。<br>二维码刷新无需重新下载文件。</footer>
<small><button id="stop">停止扫码助手</button></small></main>
<script>
let stopped=false;async function poll(){if(stopped)return;try{let r=await fetch('state',{cache:'no-store'});if(!r.ok)throw 0;let s=await r.json();
document.getElementById('title').textContent=s.title;document.getElementById('detail').textContent=s.detail;
let i=document.getElementById('image');i.hidden=!s.image;if(s.image)i.src=s.image;else i.removeAttribute('src');
document.title=s.phase==='scan'?'请微信扫码 · iCourse':'iCourse 扫码助手';
document.getElementById('run').textContent=s.run_number?'当前任务 #'+s.run_number:'';
let a=document.getElementById('run-link');a.hidden=!s.run_url;if(s.run_url)a.href=s.run_url;
}catch{document.getElementById('image').hidden=true;document.getElementById('title').textContent='正在等待本机助手';}
if(!stopped)setTimeout(poll,700);}poll();
document.getElementById('stop').onclick=async()=>{await fetch('stop',{method:'POST'});stopped=true;
document.getElementById('image').hidden=true;document.getElementById('title').textContent='扫码助手已停止';
document.getElementById('detail').textContent='可以关闭这个页面。云端任务的状态不受影响。';};
</script></html>"""


def make_handler(watcher, capability):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, code, payload, content_type):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(payload)

        def valid_host(self):
            return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

        def do_GET(self):
            if not self.valid_host():
                return self.reply(403, b"Forbidden", "text/plain")
            if self.path == f"/{capability}/":
                return self.reply(200, PAGE.encode(), "text/html; charset=utf-8")
            if self.path == f"/{capability}/state":
                return self.reply(200, json.dumps(watcher.snapshot(), ensure_ascii=False).encode(), "application/json; charset=utf-8")
            return self.reply(404, b"Not found", "text/plain")

        def do_POST(self):
            origin = self.headers.get("Origin", "")
            expected = f"http://127.0.0.1:{self.server.server_port}"
            if not self.valid_host() or self.path != f"/{capability}/stop" or origin not in ("", expected):
                return self.reply(403, b"Forbidden", "text/plain")
            watcher.stop.set()
            self.reply(200, b"{}", "application/json")
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="Bgusa8555/Fudan_iCourse_Subscriber")
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--interval", type=float, default=2)
    parser.add_argument("--duration", type=float, default=7200)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--open-now", action="store_true", help="Also show the waiting screen immediately")
    args = parser.parse_args()
    capability = secrets.token_urlsafe(24)
    watcher = Watcher(None, args.repo, run_id=args.run_id)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(watcher, capability))
    url = f"http://127.0.0.1:{server.server_port}/{capability}/"
    opener = (lambda: None) if args.no_browser else lambda: webbrowser.open(url, new=2)
    watcher.opener = opener
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if args.open_now:
        opener()
    try:
        watcher.client = GitHubClient(args.repo, load_token())
    except (GitHubError, ValueError) as exc:
        watcher.update(phase="ended", title="请先登录 GitHub", detail=str(exc), image="")
        if not args.open_now:
            opener()
        watcher.stop.wait(300)
        server.shutdown()
        server.server_close()
        return 1
    print("本机扫码助手已启动；云端需要验证时会自动打开浏览器。", flush=True)
    print(url, flush=True)
    try:
        watcher.watch(max(1, args.interval), max(1, args.duration))
    except KeyboardInterrupt:
        pass
    finally:
        watcher.stop.set()
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
