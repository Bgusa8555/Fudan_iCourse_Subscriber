"""The local browser assistant reads real artifact bytes without exposing tokens."""

import base64
from io import BytesIO
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from watch_verification import GitHubError, Watcher, make_handler, qr_from_archive, select_artifact, select_run
from http.server import ThreadingHTTPServer


PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jM0sAAAAASUVORK5CYII=")


def archive(name="wechat-" + "a" * 32 + ".png", raw=PNG):
    out = BytesIO()
    with zipfile.ZipFile(out, "w") as bundle:
        bundle.writestr(name, raw)
        bundle.writestr("page.html", '<script>throw "must never execute"</script>')
    return out.getvalue()


def run(run_id=123, status="in_progress", attempt=1):
    return {"id": run_id, "path": ".github/workflows/check.yml", "run_attempt": attempt,
            "run_number": 117, "status": status, "created_at": "2026-11-12T09:00:00Z"}


def artifact(artifact_id=456, attempt=1):
    return {"id": artifact_id, "name": f"wechat-verification-123-{attempt}-wechat-" + "a" * 32,
            "created_at": "2026-11-12T09:01:00Z", "size_in_bytes": 12000, "expired": False}


class BrowserAssistantTests(unittest.TestCase):
    def test_only_eligible_active_workflow_is_selected(self):
        other = {**run(999), "path": ".github/workflows/deploy-frontend.yml"}
        self.assertEqual(select_run([other, run(122, "completed"), run(123)])["id"], 123)

    def test_old_attempt_artifact_is_not_shown(self):
        self.assertEqual(select_artifact([artifact(1, 1), artifact(2, 2)], run(attempt=2))["id"], 2)
        self.assertIsNone(select_artifact([artifact(1, 1)], run(attempt=2)))

    def test_downloaded_image_is_displayed_without_extracting_or_running_html(self):
        self.assertEqual(qr_from_archive(archive()), "data:image/png;base64," + base64.b64encode(PNG).decode())
        with self.assertRaises(GitHubError):
            qr_from_archive(archive("../../secret.png"))
        with self.assertRaises(GitHubError):
            qr_from_archive(archive(raw=b"<html>not an image</html>"))

    def test_detecting_a_qr_opens_browser_and_refreshes_same_page(self):
        client, browser = Mock(), Mock()
        current = {"artifact": artifact()}

        def get(endpoint, **kwargs):
            if endpoint.startswith("/actions/runs?"):
                return {"workflow_runs": [run()]}
            if endpoint.endswith("/artifacts?per_page=100"):
                return {"artifacts": [current["artifact"]]}
            return archive()

        client.get.side_effect = get
        watcher = Watcher(client, "owner/repo", opener=browser)
        watcher.tick()
        browser.assert_called_once()
        self.assertEqual(watcher.snapshot()["phase"], "scan")
        count = client.get.call_count
        watcher.tick()
        self.assertEqual(client.get.call_count - count, 2, "cached QR does not need another download")
        current["artifact"] = artifact(789)
        watcher.tick()
        browser.assert_called_once()
        self.assertEqual(watcher.cached[-1], 789)

    def test_finished_task_clears_qr_and_does_not_open_browser(self):
        client, browser = Mock(), Mock()
        client.get.return_value = {"workflow_runs": [{**run(status="completed"), "conclusion": "failure"}]}
        watcher = Watcher(client, "owner/repo", opener=browser)
        watcher.update(image="stale-qr")
        watcher.tick()
        self.assertEqual(watcher.snapshot()["image"], "")
        self.assertEqual(watcher.snapshot()["phase"], "ended")
        browser.assert_not_called()

    def test_network_error_hides_stale_qr(self):
        client = Mock()
        client.get.side_effect = GitHubError("network error")
        watcher = Watcher(client, "owner/repo")
        watcher.update(image="stale-qr")
        watcher.stop.wait = Mock(side_effect=lambda *args: watcher.stop.set())
        watcher.watch(1, 60)
        self.assertEqual(watcher.snapshot()["image"], "")

    def test_browser_receives_status_only_and_host_capability_are_checked(self):
        watcher = Watcher(Mock(), "owner/repo")
        watcher.update(image="data:image/png;base64,abc")
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(watcher, "capability"))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with urlopen(base + "/capability/state") as response:
                self.assertEqual(json.load(response)["image"], "data:image/png;base64,abc")
                self.assertEqual(response.headers["Cache-Control"], "no-store")
                self.assertIsNone(response.headers.get("Access-Control-Allow-Origin"))
            for request in (Request(base + "/wrong/state"), Request(base + "/capability/state", headers={"Host": "attacker.example"})):
                with self.assertRaises(HTTPError):
                    urlopen(request)
            with urlopen(base + "/capability/") as response:
                page = response.read().decode()
                self.assertNotIn("Authorization", page)
                self.assertIn("setTimeout(poll,700)", page)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
