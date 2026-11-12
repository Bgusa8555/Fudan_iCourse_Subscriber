"""Authentication regression tests; no credentials or live school requests."""

import base64
import json
from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
from io import StringIO
import os
from pathlib import Path
import smtplib
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import requests

from src.api import verification
from src.api.verification import VerificationError, resolve_login_token
from src.api.webvpn import WebVPNSession, get_vpn_url
from src.runtime import config


PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jM0sAAAAASUVORK5CYII="
)
HEADERS = {"Origin": config.WEBVPN_BASE}
CONTEXT = {
    "authModuleCode": "userAndPwd",
    "authChainCode": "password-chain",
    "entityId": config.ICOURSE_BASE,
    "requestType": "chain_type",
    "lck": "current-lck",
    "authPara": {"loginName": "student", "password": "sensitive-password"},
}
CHALLENGE = {
    "code": 200,
    "second": True,
    "moduleCodes": ["userAndSms", "qr"],
    "authChainCode": "second-chain",
    "requestNumber": "second-request",
    "userName": "student",
}


def response(data=None, *, url="", text="", status=200, content=b""):
    result = Mock(spec=requests.Response)
    result.status_code = status
    result.url = url
    result.text = text
    result.content = content
    result.history = []
    result.headers = {}
    result.json.return_value = data
    if status >= 400:
        result.raise_for_status.side_effect = requests.HTTPError(response=result)
    return result


def qr_response(token="qr-secret"):
    return response({
        "code": "200",
        "data": {
            "qrToken": token,
            "qrMsg": "data:image/png;base64," + base64.b64encode(PNG).decode(),
        },
    })


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.stack.enter_context(patch.multiple(
            config,
            AUTH_VERIFICATION_TIMEOUT=600,
            AUTH_VERIFICATION_MAX_QR_CODES=3,
            AUTH_VERIFICATION_DIR=self.directory,
            SMTP_EMAIL="sender@example.com",
            SMTP_PASSWORD="smtp-secret",
            RECEIVER_EMAIL="receiver@example.com",
        ))
        self.stack.enter_context(patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "ICOURSE_VERIFICATION_BRIDGE": ""}))
        self.smtp = self.stack.enter_context(patch.object(verification.smtplib, "SMTP_SSL"))
        self.smtp.return_value.send_message.return_value = {}
        self.starttls = self.stack.enter_context(patch.object(verification.smtplib, "SMTP"))
        self.starttls.return_value.send_message.return_value = {}
        self.background = self.stack.enter_context(patch.object(verification._WeChatVerification, "_send_email_in_background"))
        self.stack.enter_context(patch.object(verification.webbrowser, "open", return_value=False))
        self.output = self.stack.enter_context(redirect_stdout(StringIO()))
        self.pause = self.stack.enter_context(patch.object(verification.time, "sleep"))
        self.session = Mock(spec=requests.Session)

    def resolve(self, data=None):
        return resolve_login_token(
            self.session, deepcopy(CHALLENGE if data is None else data),
            deepcopy(CONTEXT), route=get_vpn_url, headers=HEADERS, label="iCourse CAS",
        )

    def assert_clean(self):
        self.assertEqual(list(Path(self.directory).iterdir()), [])
        for secret in ("qr-secret", "sensitive-password", "current-lck", "smtp-secret"):
            self.assertNotIn(secret, self.output.getvalue())

    def test_normal_password_login_does_not_send_verification(self):
        self.assertEqual(self.resolve({"code": "200", "loginToken": "real-token"}), "real-token")
        self.smtp.assert_not_called()
        self.session.post.assert_not_called()

    def test_missing_token_does_not_invent_a_qr_challenge(self):
        with self.assertRaisesRegex(RuntimeError, "no loginToken"):
            self.resolve({"code": 200, "message": "unknown state"})
        self.smtp.assert_not_called()
        self.session.post.assert_not_called()

    def test_bad_password_does_not_send_verification_email(self):
        with self.assertRaisesRegex(RuntimeError, "code=401"):
            self.resolve({"code": 401, "message": "bad password"})
        self.smtp.assert_not_called()

    def test_scan_resumes_the_original_transaction_and_cleans_files(self):
        self.session.post.side_effect = [qr_response(), response({"code": 200, "loginToken": "real-token"})]
        page_seen = []

        def confirm(*args, **kwargs):
            pages = list(Path(self.directory).glob("*.html"))
            page_seen.extend(pages)
            self.assertEqual(len(pages), 1)
            page = pages[0].read_text(encoding="utf-8")
            self.assertIn("data:image/png;base64,", page)
            self.assertNotIn("qr-secret", page)
            self.assertNotIn("sensitive-password", page)

        self.smtp.return_value.send_message.side_effect = confirm
        self.assertEqual(self.resolve(), "real-token")
        self.assertTrue(page_seen)
        qr_call, auth_call = self.session.post.call_args_list
        self.assertEqual(qr_call.args[0], get_vpn_url(config.IDP_BASE + "/idp/authn/getAuthQr"))
        self.assertEqual(qr_call.kwargs["json"], {"entityId": config.ICOURSE_BASE})
        payload = auth_call.kwargs["json"]
        self.assertEqual(auth_call.args[0], get_vpn_url(config.IDP_BASE + "/idp/authn/authExecute"))
        self.assertEqual(payload["lck"], CONTEXT["lck"])
        self.assertEqual(payload["authChainCode"], CHALLENGE["authChainCode"])
        self.assertEqual(payload["requestNumber"], CHALLENGE["requestNumber"])
        self.assertEqual(payload["authPara"], {"loginName": "student", "qrToken": "qr-secret"})
        self.assertEqual(auth_call.kwargs["headers"], HEADERS)
        self.assert_clean()

    def test_email_contains_actual_school_image_and_no_session_secrets(self):
        self.session.post.side_effect = [qr_response(), response({"code": 200, "loginToken": "ok"})]
        self.resolve()
        server = self.smtp.return_value
        message = server.send_message.call_args.args[0]
        self.assertEqual(message["To"], "receiver@example.com")
        images = [part for part in message.walk() if part.get_content_maintype() == "image"]
        self.assertEqual(len(images), 1)
        self.assertEqual(images[0].get_payload(decode=True), PNG)
        self.assertEqual(images[0]["Content-ID"], "<wechat-qr>")
        self.assertNotIn("qr-secret", message.as_string())
        self.assertNotIn("sensitive-password", message.as_string())
        self.assert_clean()

    def test_temporary_network_errors_keep_same_qr_and_session(self):
        self.session.post.side_effect = [
            qr_response(), requests.Timeout(), requests.ConnectionError(),
            response({"code": 200, "loginToken": "ok"}),
        ]
        self.assertEqual(self.resolve(), "ok")
        self.assertEqual(self.smtp.return_value.send_message.call_count, 1)
        payloads = [call.kwargs["json"] for call in self.session.post.call_args_list[1:]]
        self.assertTrue(all(payload == payloads[0] for payload in payloads))
        self.assert_clean()

    def test_temporary_server_error_keeps_waiting(self):
        self.session.post.side_effect = [qr_response(), response(status=503), response({"code": 200, "loginToken": "ok"})]
        self.assertEqual(self.resolve(), "ok")
        self.assert_clean()

    def test_pending_state_waits_until_confirmation(self):
        self.session.post.side_effect = [
            qr_response(), response({"code": 202, "message": "等待扫码确认"}),
            response({"code": 200, "loginToken": "ok"}),
        ]
        self.assertEqual(self.resolve(), "ok")
        self.pause.assert_called_once()
        self.assert_clean()

    def test_expired_qr_sends_replacement_without_relogging(self):
        tokens_used = []

        def post(url, **kwargs):
            if url.endswith("getAuthQr"):
                return qr_response("qr-secret" if not tokens_used else "replacement-secret")
            token = kwargs["json"]["authPara"]["qrToken"]
            tokens_used.append(token)
            return response({"code": 408, "message": "二维码已过期"}) if len(tokens_used) == 1 else response({"code": 200, "loginToken": "ok"})

        self.session.post.side_effect = post
        self.assertEqual(self.resolve(), "ok")
        self.assertEqual(tokens_used, ["qr-secret", "replacement-secret"])
        self.assertEqual(self.smtp.return_value.send_message.call_count, 2)
        self.assert_clean()

    def test_expired_qr_count_is_bounded(self):
        self.session.post.side_effect = [item for _ in range(3) for item in (qr_response(), response({"code": 408, "message": "expired"}))]
        with self.assertRaises(VerificationError):
            self.resolve()
        self.assertEqual(self.session.post.call_count, 6)
        self.assert_clean()

    def test_timeout_is_a_non_retryable_verification_error(self):
        with patch.object(config, "AUTH_VERIFICATION_TIMEOUT", 1):
            self.session.post.side_effect = [qr_response(), requests.Timeout()]
            with patch.object(verification.time, "monotonic", side_effect=range(100)):
                with self.assertRaisesRegex(VerificationError, "超时"):
                    self.resolve()
        self.assert_clean()

    def test_phone_rejection_stops_and_cleans_up(self):
        self.session.post.side_effect = [qr_response(), response({"code": 403, "message": "用户拒绝"})]
        with self.assertRaises(VerificationError):
            self.resolve()
        self.assertEqual(self.session.post.call_count, 2)
        self.assert_clean()

    def test_success_code_without_a_token_is_not_success(self):
        self.session.post.side_effect = [qr_response(), response({"code": 200})]
        with self.assertRaises(VerificationError):
            self.resolve()
        self.assert_clean()

    def test_unsupported_factor_does_not_send_qr(self):
        with self.assertRaisesRegex(VerificationError, "userAndOtp"):
            self.resolve({**CHALLENGE, "moduleCodes": ["userAndOtp"]})
        self.session.post.assert_not_called()
        self.smtp.assert_not_called()

    def test_missing_transaction_number_does_not_start_new_transaction(self):
        data = {key: value for key, value in CHALLENGE.items() if key != "requestNumber"}
        with self.assertRaisesRegex(VerificationError, "requestNumber"):
            self.resolve(data)
        self.session.post.assert_not_called()

    def test_ci_without_mail_configuration_fails_without_waiting(self):
        self.session.post.return_value = qr_response()
        with patch.object(config, "SMTP_PASSWORD", ""):
            with self.assertRaisesRegex(VerificationError, "SMTP_EMAIL"):
                self.resolve()
        self.assertEqual(self.session.post.call_count, 1)
        self.assert_clean()

    def test_smtp_failure_does_not_leave_unreachable_wait_in_ci(self):
        self.session.post.return_value = qr_response()
        self.smtp.side_effect = smtplib.SMTPException("private transport error")
        self.starttls.side_effect = smtplib.SMTPException("private transport error")
        with self.assertRaises(VerificationError):
            self.resolve()
        self.assertEqual(self.session.post.call_count, 1)
        self.assertNotIn("private transport error", self.output.getvalue())
        self.assert_clean()

    def test_smtp_disconnect_uses_starttls_then_resumes_same_login(self):
        self.session.post.side_effect = [qr_response(), response({"code": 200, "loginToken": "ok"})]
        self.smtp.side_effect = smtplib.SMTPServerDisconnected("private server message")
        self.assertEqual(self.resolve(), "ok")
        self.assertEqual(self.smtp.call_count, 1)
        self.starttls.assert_called_once()
        self.assertEqual(self.starttls.call_args.args, (config.SMTP_HOST, 587))
        server = self.starttls.return_value
        calls = [call[0] for call in server.method_calls]
        self.assertLess(calls.index("starttls"), calls.index("login"))
        self.assertTrue(server.starttls.call_args.kwargs["context"].check_hostname)
        self.assertEqual(server.ehlo.call_count, 2)
        self.assertNotIn("private server message", self.output.getvalue())
        self.assertEqual(self.session.post.call_count, 2)
        self.assert_clean()

    def test_smtp_disconnect_during_auth_is_retried(self):
        self.session.post.side_effect = [qr_response(), response({"code": 200, "loginToken": "ok"})]
        self.smtp.return_value.login.side_effect = smtplib.SMTPServerDisconnected("private auth message")
        self.assertEqual(self.resolve(), "ok")
        self.smtp.return_value.send_message.assert_not_called()
        self.starttls.return_value.send_message.assert_called_once()
        self.assertIn("认证失败", self.output.getvalue())
        self.assert_clean()

    def test_smtp_auth_rejection_stops_mail_retries(self):
        self.session.post.return_value = qr_response()
        self.smtp.return_value.login.side_effect = smtplib.SMTPAuthenticationError(535, b"smtp-secret")
        with self.assertRaises(VerificationError):
            self.resolve()
        self.assertEqual(self.smtp.call_count, 1)
        self.starttls.assert_not_called()
        self.assertIn("SMTP 535", self.output.getvalue())
        self.assert_clean()

    def test_smtp_retries_are_bounded_when_both_ports_disconnect(self):
        self.session.post.return_value = qr_response()
        self.smtp.side_effect = smtplib.SMTPServerDisconnected()
        self.starttls.side_effect = smtplib.SMTPServerDisconnected()
        with self.assertRaises(VerificationError):
            self.resolve()
        self.assertEqual(self.smtp.call_count, 2)
        self.assertEqual(self.starttls.call_count, 2)
        self.assertEqual(self.session.post.call_count, 1)
        self.assert_clean()

    def test_starttls_failure_never_sends_cleartext_credentials(self):
        self.session.post.return_value = qr_response()
        self.smtp.side_effect = OSError()
        self.starttls.return_value.starttls.side_effect = smtplib.SMTPNotSupportedError()
        with self.assertRaises(VerificationError):
            self.resolve()
        self.starttls.return_value.login.assert_not_called()
        self.starttls.return_value.send_message.assert_not_called()
        self.assert_clean()

    def test_custom_smtp_server_does_not_switch_to_qq_port(self):
        self.session.post.side_effect = [qr_response(), response({"code": 200, "loginToken": "ok"})]
        working_server = self.smtp.return_value
        self.smtp.side_effect = [smtplib.SMTPServerDisconnected(), working_server]
        with patch.object(config, "SMTP_HOST", "smtp.example.com"):
            self.assertEqual(self.resolve(), "ok")
        self.starttls.assert_not_called()
        self.assert_clean()

    def test_artifact_entry_keeps_ci_waiting_when_email_fails(self):
        self.session.post.side_effect = [qr_response(), response({"code": 200, "loginToken": "ok"})]
        url = "https://github.com/owner/repo/actions/runs/123/artifacts/456"
        with patch.object(verification._WeChatVerification, "_publish_actions_entry", return_value=url), \
             patch.object(verification._WeChatVerification, "_send_email", return_value=False):
            self.assertEqual(self.resolve(), "ok")
        self.assertIn(url, self.output.getvalue())
        self.assertIn("二维码下载入口", self.output.getvalue())
        self.assert_clean()

    def test_confirmation_starts_while_background_email_is_still_blocked(self):
        started = threading.Event()
        release = threading.Event()
        done = threading.Event()

        def blocked_mail(*args):
            started.set()
            release.wait(5)
            done.set()

        def post(url, **kwargs):
            if url.endswith("getAuthQr"):
                return qr_response()
            self.assertTrue(started.wait(1))
            self.assertFalse(release.is_set())
            return response({"code": 200, "loginToken": "ok"})

        self.background.side_effect = blocked_mail
        self.session.post.side_effect = post
        try:
            with patch.object(verification._WeChatVerification, "_publish_actions_entry", return_value="https://github.com/owner/repo/actions/runs/1/artifacts/2"):
                self.assertEqual(self.resolve(), "ok")
        finally:
            release.set()
            self.assertTrue(done.wait(1))
        self.assert_clean()

    def test_local_browser_is_opened_automatically_before_mail_delivery(self):
        self.session.post.side_effect = [qr_response(), response({"code": 200, "loginToken": "ok"})]
        with patch.dict(os.environ, {"GITHUB_ACTIONS": ""}), \
             patch.object(verification.webbrowser, "open", return_value=True) as browser:
            self.assertEqual(self.resolve(), "ok")
        self.assertTrue(browser.call_args.args[0].startswith("file:"))
        self.smtp.assert_not_called()
        self.assert_clean()

    def test_real_bridge_requests_image_and_html_then_marks_cleanup(self):
        self.session.post.side_effect = [qr_response(), response({"code": 200, "loginToken": "ok"})]
        bridge = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        seen = []

        def upload_on_poll(*args):
            for request_path in bridge.glob("*.request.json"):
                manifest = json.loads(request_path.read_text(encoding="utf-8"))
                seen.append(manifest)
                self.assertEqual(len(manifest["files"]), 2)
                self.assertTrue(all(Path(name).exists() for name in manifest["files"]))
                result = bridge / f"{manifest['id']}.result.json"
                result.write_text(json.dumps({"url": "https://github.com/owner/repo/actions/runs/123/artifacts/456"}), encoding="utf-8")

        with patch.dict(os.environ, {"ICOURSE_VERIFICATION_BRIDGE": str(bridge)}), \
             patch.object(config, "SMTP_PASSWORD", ""), \
             patch.object(verification.time, "sleep", side_effect=upload_on_poll):
            self.assertEqual(self.resolve(), "ok")
        self.assertEqual(len(seen), 1)
        self.assertTrue((bridge / f"{seen[0]['id']}.remove").exists())
        self.assert_clean()

    def test_bridge_upload_failure_still_uses_email(self):
        self.session.post.side_effect = [qr_response(), response({"code": 200, "loginToken": "ok"})]
        bridge = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))

        def fail_upload(*args):
            for request_path in bridge.glob("*.request.json"):
                manifest = json.loads(request_path.read_text(encoding="utf-8"))
                (bridge / f"{manifest['id']}.result.json").write_text("{}", encoding="utf-8")

        with patch.dict(os.environ, {"ICOURSE_VERIFICATION_BRIDGE": str(bridge)}), \
             patch.object(verification.time, "sleep", side_effect=fail_upload):
            self.assertEqual(self.resolve(), "ok")
        self.smtp.return_value.send_message.assert_called_once()
        self.assert_clean()

    def test_local_without_mail_can_use_page(self):
        self.session.post.side_effect = [qr_response(), response({"code": 200, "loginToken": "ok"})]
        with patch.dict(os.environ, {"GITHUB_ACTIONS": ""}), patch.object(config, "SMTP_PASSWORD", ""):
            self.assertEqual(self.resolve(), "ok")
        self.assertIn("HTML", self.output.getvalue())
        self.assert_clean()

    def test_invalid_qr_image_fails_closed(self):
        self.session.post.return_value = response({"code": 200, "data": {
            "qrToken": "qr-secret", "qrMsg": "data:image/png;base64,bm90LWFuLWltYWdl",
        }})
        with self.assertRaises(VerificationError):
            self.resolve()
        self.smtp.assert_not_called()
        self.assert_clean()

    def test_school_image_url_is_fetched_through_same_vpn_session(self):
        self.session.post.side_effect = [response({"code": 200, "data": {
            "qrToken": "qr-secret", "qrMsg": config.IDP_BASE + "/idp/qr/current.png",
        }}), response({"code": 200, "loginToken": "ok"})]
        self.session.get.return_value = response(content=PNG)
        self.assertEqual(self.resolve(), "ok")
        self.assertEqual(self.session.get.call_args.args[0], get_vpn_url(config.IDP_BASE + "/idp/qr/current.png"))
        self.assert_clean()

    def test_qr_transport_failure_is_not_an_outer_login_retry(self):
        self.session.post.side_effect = requests.Timeout("https://secret.example/?token=qr-secret")
        with self.assertRaises(VerificationError) as caught:
            self.resolve()
        self.assertNotIn("qr-secret", str(caught.exception))
        self.assert_clean()

    def test_icourse_completes_ticket_exchange_after_scan_using_same_session(self):
        vpn = WebVPNSession()
        vpn.session = self.session
        ticket = config.ICOURSE_BASE + "/casapi/index.php?ticket=cas-secret"
        self.session.get.side_effect = [
            response(),
            response(url=get_vpn_url(config.IDP_BASE + "/ac/?lck=cas-lck")),
            response({"data": "fake-public-key"}),
            response(),
            response({"code": 200}),
        ]
        self.session.post.side_effect = [
            response({"data": [{"moduleCode": "userAndPwd", "authChainCode": "password-chain"}], "requestType": "chain_type"}),
            response(CHALLENGE), qr_response(), response({"code": 200, "loginToken": "real-token"}),
            response(text=f'var locationValue = "{ticket}";'),
        ]
        with patch.object(vpn, "_encrypt_password", return_value="encrypted"):
            self.assertTrue(vpn.authenticate_icourse("student", "password"))
        self.assertIs(vpn.session, self.session)
        self.assertEqual(self.session.post.call_args.kwargs["data"], {"loginToken": "real-token"})
        self.assertEqual(self.session.get.call_args_list[-2].args[0], get_vpn_url(ticket))
        self.assertEqual(self.session.post.call_args_list[3].kwargs["json"]["lck"], "cas-lck")
        self.assert_clean()

    def test_webvpn_initial_login_can_also_complete_scan(self):
        vpn = WebVPNSession()
        vpn.session = self.session
        self.session.post.side_effect = [response(CHALLENGE), qr_response(), response({"code": 200, "loginToken": "vpn-token"})]
        with patch.object(vpn, "_get_auth_context", return_value=("vpn-lck", config.WEBVPN_BASE)), \
             patch.object(vpn, "_query_auth_methods", return_value=("password-chain", "chain_type")), \
             patch.object(vpn, "_get_public_key", return_value="public-key"), \
             patch.object(vpn, "_encrypt_password", return_value="encrypted"), \
             patch.object(vpn, "_get_cas_ticket", return_value="https://webvpn.fudan.edu.cn/ticket") as ticket, \
             patch.object(vpn, "_establish_session") as establish:
            self.assertTrue(vpn.login("student", "password"))
        self.assertTrue(vpn.logged_in)
        ticket.assert_called_once_with("vpn-token")
        establish.assert_called_once()
        self.assertEqual(self.session.post.call_args.args[0], config.IDP_BASE + "/idp/authn/authExecute")
        self.assert_clean()


if __name__ == "__main__":
    unittest.main()
