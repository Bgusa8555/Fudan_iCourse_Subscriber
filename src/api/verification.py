"""Continue an IDP authentication transaction through WeChat QR verification.

The endpoints and payloads follow Fudan's loginSecondContent browser flow:
getAuthQr returns qrMsg/qrToken; authExecute waits for the phone confirmation.
The requests session, lck, and requestNumber must survive the entire exchange.
"""

import base64
import binascii
import html
import os
from pathlib import Path
import re
import smtplib
import time
import uuid
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urljoin, urlparse

import requests

from src.runtime import config


class VerificationError(RuntimeError):
    """An interactive verification could not finish; do not restart login."""


def resolve_login_token(session, data, context, *, route, headers, label):
    """Return a real loginToken, completing advertised QR stages if needed.

    A missing token alone is not evidence of a QR challenge. Only the IDP's
    explicit second/moduleCodes response can start interactive verification.
    """
    verifier = _WeChatVerification(session, route, headers, label)
    for _ in range(5):
        if not isinstance(data, dict):
            raise RuntimeError(f"{label}: authentication response is not an object")
        if str(data.get("code")) != "200":
            raise RuntimeError(f"{label}: authentication failed (code={data.get('code')})")
        if data.get("second"):
            try:
                data = verifier.wait(data, context)
            except VerificationError:
                raise
            except (requests.RequestException, ValueError, OSError) as exc:
                # Interactive failures must not fall into the outer password
                # retry loop. Do not expose URLs, cookies, or QR tokens there.
                raise VerificationError(
                    f"{label}: 无法继续微信扫码验证 ({type(exc).__name__})"
                ) from None
            continue
        token = data.get("loginToken")
        if isinstance(token, str) and token:
            print("    loginToken: OK")
            return token
        raise RuntimeError(
            f"{label}: no loginToken or explicit second-factor challenge "
            f"(code={data.get('code')}, fields={','.join(sorted(data))})"
        )
    raise VerificationError(f"{label}: too many additional verification stages")


class _WeChatVerification:
    def __init__(self, session, route, headers, label):
        self.session = session
        self.route = route
        self.headers = headers
        self.label = label
        self.deadline = None

    def _remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise VerificationError(
                f"{self.label}: 微信扫码验证等待超时，请重新运行并在期限内确认。"
            )
        return remaining

    def _pause(self):
        time.sleep(min(2, self._remaining()))

    def _post(self, endpoint, payload, read_limit=None):
        remaining = self._remaining()
        response = self.session.post(
            self.route(f"{config.IDP_BASE}/idp/authn/{endpoint}"),
            json=payload,
            headers=self.headers,
            timeout=(min(10, remaining), min(read_limit or remaining, remaining)),
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise VerificationError(f"{self.label}: invalid verification response")
        return data

    def wait(self, challenge, context):
        modules = challenge.get("moduleCodes") or []
        if "qr" not in modules:
            raise VerificationError(
                f"{self.label}: 学校要求的二次验证类型为 {modules!r}，"
                "当前入口支持微信扫码（qr）。"
            )
        chain = challenge.get("authChainCode")
        request_number = challenge.get("requestNumber")
        if not chain or request_number in (None, ""):
            raise VerificationError(
                f"{self.label}: QR challenge is missing authChainCode/requestNumber"
            )
        if config.AUTH_VERIFICATION_TIMEOUT <= 0 or config.AUTH_VERIFICATION_MAX_QR_CODES <= 0:
            raise VerificationError("微信扫码验证已禁用，请设置正数的等待时间和二维码数量。")
        if self.deadline is None:
            self.deadline = time.monotonic() + config.AUTH_VERIFICATION_TIMEOUT

        # Copy only transaction identifiers, never the password authPara.
        payload = {
            "authModuleCode": "qr",
            "authChainCode": chain,
            "entityId": context["entityId"],
            "requestNumber": request_number,
            "requestType": context["requestType"],
            "lck": context["lck"],
            "authPara": {
                "loginName": challenge.get("userName")
                or context.get("authPara", {}).get("loginName")
                or config.STUDENT_ID,
            },
        }
        print(f"[Verify] {self.label} 需要微信扫码确认，正在准备二维码...", flush=True)
        for qr_index in range(config.AUTH_VERIFICATION_MAX_QR_CODES):
            qr = self._post("getAuthQr", {"entityId": context["entityId"]}, 60)
            details = qr.get("data")
            if str(qr.get("code")) != "200" or not isinstance(details, dict):
                raise VerificationError(
                    f"{self.label}: could not obtain QR code (code={qr.get('code')})"
                )
            if not details.get("qrToken") or not isinstance(details.get("qrMsg"), str):
                raise VerificationError(f"{self.label}: QR response has no qrToken/qrMsg")
            payload["authPara"]["qrToken"] = details["qrToken"]
            image_bytes, subtype = self._read_image(details["qrMsg"])
            paths = []
            try:
                self._publish(image_bytes, subtype, paths)
                print(
                    f"[Verify] 请用绑定学校账号的微信扫码并确认；"
                    f"本次最多再等待 {int(self._remaining())} 秒，确认后任务自动继续。",
                    flush=True,
                )
                while True:
                    try:
                        # This is the browser's blocking confirmation request,
                        # not a fresh password login or a separate browser session.
                        result = self._post("authExecute", payload)
                    except (requests.Timeout, requests.ConnectionError):
                        print("[Verify] 网络暂时中断，继续等待同一二维码的确认...", flush=True)
                        self._pause()
                        continue
                    except requests.HTTPError as exc:
                        if exc.response is not None and (
                            exc.response.status_code == 429 or exc.response.status_code >= 500
                        ):
                            self._pause()
                            continue
                        raise VerificationError(f"{self.label}: verification HTTP request failed") from None
                    except ValueError:
                        raise VerificationError(f"{self.label}: verification returned invalid JSON") from None
                    if str(result.get("code")) == "200" and (
                        result.get("loginToken") or result.get("second")
                    ):
                        print("[Verify] 微信扫码验证完成，继续当前登录流程。", flush=True)
                        return result
                    message = str(result.get("message") or result.get("msg") or "").lower()
                    if re.search(r"过期|失效|超时|expired|timeout|timed out", message):
                        break
                    if re.search(r"等待|未扫码|未扫描|待确认|pending|waiting", message):
                        self._pause()
                        continue
                    raise VerificationError(
                        f"{self.label}: 微信扫码被拒绝或验证失败 (code={result.get('code')})"
                    )
            finally:
                for path in paths:
                    path.unlink(missing_ok=True)
            self._remaining()
            if qr_index + 1 < config.AUTH_VERIFICATION_MAX_QR_CODES:
                print("[Verify] 二维码已过期，正在发送新的二维码...", flush=True)
                self._pause()
        raise VerificationError(f"{self.label}: 二维码已过期，请重新运行后扫码确认。")

    def _read_image(self, source):
        if source.startswith("data:image/"):
            try:
                header, encoded = source.split(",", 1)
                if not header.endswith(";base64") or len(encoded) > 3 * 1024 * 1024:
                    raise ValueError
                raw = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error):
                raise VerificationError("学校返回的二维码图片格式无效。") from None
        else:
            image_url = urljoin(config.IDP_BASE + "/", source)
            parsed = urlparse(image_url)
            if parsed.scheme not in ("https", "http") or not parsed.hostname:
                raise VerificationError("学校返回的二维码图片地址无效。")
            if parsed.hostname == urlparse(config.IDP_BASE).hostname:
                image_url = self.route(image_url)
            response = self.session.get(image_url, timeout=min(30, self._remaining()))
            response.raise_for_status()
            raw = response.content
        if len(raw) > 2 * 1024 * 1024:
            raise VerificationError("学校返回的二维码图片过大。")
        if raw.startswith(b"\x89PNG\r\n\x1a\n"):
            return raw, "png"
        if raw.startswith(b"\xff\xd8\xff"):
            return raw, "jpeg"
        if raw.startswith((b"GIF87a", b"GIF89a")):
            return raw, "gif"
        raise VerificationError("学校没有返回可识别的二维码图片，请检查认证接口。")

    def _publish(self, image_bytes, subtype, paths):
        directory = Path(config.AUTH_VERIFICATION_DIR).resolve()
        directory.mkdir(parents=True, exist_ok=True)
        stem = "wechat-" + uuid.uuid4().hex
        image_path = directory / f"{stem}.{subtype}"
        page_path = directory / f"{stem}.html"
        # Record paths before writing so a partially written file is cleaned too.
        paths.extend((image_path, page_path))
        image_path.write_bytes(image_bytes)
        image_data = base64.b64encode(image_bytes).decode("ascii")
        page_path.write_text(
            '<!doctype html><html lang="zh-CN"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta name="referrer" content="no-referrer"><title>微信扫码验证</title>'
            '<body style="font-family:system-ui;text-align:center;padding:40px">'
            f'<h1>微信扫码验证</h1><p>{html.escape(self.label)}</p>'
            '<p>请用绑定学校账号的微信扫码并确认，完成后任务会自动继续。</p>'
            f'<img alt="微信验证二维码" style="width:280px;max-width:100%;image-rendering:pixelated" '
            f'src="data:image/{subtype};base64,{image_data}">'
            f'<p>本次剩余等待时间约 {int(self._remaining())} 秒；请以最新邮件中的二维码为准。</p>'
            '</body></html>',
            encoding="utf-8",
        )
        try:
            directory.chmod(0o700)
            image_path.chmod(0o600)
            page_path.chmod(0o600)
        except OSError:
            pass  # Windows permissions are inherited from the local directory.
        print(f"[Verify] 本机扫码入口：{page_path}", flush=True)
        sent = self._send_email(image_bytes, subtype)
        if sent:
            print("[Verify] 二维码已发送到 RECEIVER_EMAIL，请查看最新的验证邮件。", flush=True)
        elif os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
            raise VerificationError(
                "无法发送微信扫码入口。请检查 SMTP_EMAIL、SMTP_PASSWORD、"
                "RECEIVER_EMAIL 后重新运行；GitHub Actions 需要邮件投递成功才能等待扫码。"
            )
        else:
            print("[Verify] 未发送邮件，请在本机打开上面的 HTML 页面扫码。", flush=True)

    def _send_email(self, image_bytes, subtype):
        if not all((config.SMTP_EMAIL, config.SMTP_PASSWORD, config.RECEIVER_EMAIL)):
            return False
        message = MIMEMultipart("related")
        message["Subject"] = "[FiCS] 请使用微信扫码完成登录验证"
        message["From"] = config.SMTP_EMAIL
        message["To"] = config.RECEIVER_EMAIL
        alternative = MIMEMultipart("alternative")
        alternative.attach(MIMEText(
            "学校要求微信扫码验证。请查看邮件内的二维码或附件，"
            "用绑定学校账号的微信扫码并确认，当前任务会自动继续。",
            "plain", "utf-8",
        ))
        alternative.attach(MIMEText(
            f'<p>{html.escape(self.label)} 需要微信扫码确认。</p>'
            '<p>请使用绑定学校账号的微信扫码并确认，完成后当前任务自动继续。</p>'
            '<p>如收到多封邮件，请使用最新的一封。</p>'
            '<p><img src="cid:wechat-qr" alt="微信验证二维码" width="280"></p>'
            f'<p>本次任务剩余等待时间约 {int(self._remaining())} 秒。</p>',
            "html", "utf-8",
        ))
        message.attach(alternative)
        image = MIMEImage(image_bytes, _subtype=subtype)
        image.add_header("Content-ID", "<wechat-qr>")
        image.add_header("Content-Disposition", "inline", filename=f"wechat-qr.{subtype}")
        message.attach(image)
        try:
            with smtplib.SMTP_SSL(
                config.SMTP_HOST, config.SMTP_PORT, timeout=min(15, self._remaining())
            ) as server:
                server.login(config.SMTP_EMAIL, config.SMTP_PASSWORD)
                server.send_message(message)
            return True
        except (OSError, smtplib.SMTPException) as exc:
            print(f"[Verify] 验证邮件发送失败 ({type(exc).__name__})。", flush=True)
            return False
