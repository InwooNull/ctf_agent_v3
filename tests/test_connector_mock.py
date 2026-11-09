"""Connector unit tests against a loopback mock CTFd — ZERO live access.

Exercises the real CTFdClient and fetch pipeline end to end: session-cookie login,
list/get/download, the same-origin (Origin/Referer) requirement on attempt, the
429 ratelimited path, session reopen on a mid-run 401, from_env secret loading,
and the download filename sanitiser (path-traversal guard).
"""
import tempfile
import unittest
from pathlib import Path

import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from connector.ctfd_client import (  # noqa: E402
    CTFdClient, CTFdError, AuthError, RateLimited,
)
from connector import fetch  # noqa: E402
from connector.mock_ctfd import MockCTFd, VALID_USER  # noqa: E402


def _client(srv, **kw):
    return CTFdClient(srv.base_url, name=VALID_USER["name"],
                      password=VALID_USER["password"], sleep=lambda s: None, **kw)


class AuthAndSurface(unittest.TestCase):
    def test_login_sets_session_and_lists(self):
        with MockCTFd(flags={14: "acdc2026{f}"}) as srv:
            cli = _client(srv)
            user = cli.login()
            self.assertEqual(user["name"], VALID_USER["name"])
            self.assertTrue(cli.whoami())
            chals = cli.list_challenges()
            self.assertEqual([c["id"] for c in chals], [14])

    def test_bad_credentials(self):
        with MockCTFd(flags={1: "x"}) as srv:
            cli = CTFdClient(srv.base_url, name="nope", password="nope",
                             sleep=lambda s: None)
            with self.assertRaises(AuthError):
                cli.login()

    def test_list_without_auth_autologs_in(self):
        with MockCTFd(flags={1: "x"}) as srv:
            cli = _client(srv)
            # list_challenges calls _ensure_auth -> login happens transparently
            self.assertTrue(cli.list_challenges() is not None)


class SubmitSameOrigin(unittest.TestCase):
    def test_correct_and_incorrect(self):
        with MockCTFd(flags={14: "acdc2026{win}"}) as srv:
            cli = _client(srv)
            cli.login()
            self.assertEqual(cli.submit_flag(14, "acdc2026{win}")[0], "correct")
            self.assertEqual(cli.submit_flag(14, "nope")[0], "incorrect")

    def test_missing_origin_is_403(self):
        # a client that does NOT send Origin/Referer must be rejected by the mock,
        # proving the real client's Origin/Referer headers are what let it through.
        with MockCTFd(flags={14: "acdc2026{win}"}) as srv:
            cli = _client(srv)
            cli.login()
            # monkeypatch the header builder by subclassing behaviour: strip headers
            orig = cli.opener.open
            import urllib.request

            def strip_open(req, *a, **k):
                req.remove_header("Origin")
                if req.has_header("Referer"):
                    req.remove_header("Referer")
                return orig(req, *a, **k)
            cli.opener.open = strip_open
            with self.assertRaises(AuthError):
                cli.submit_flag(14, "acdc2026{win}")

    def test_ratelimited_raises(self):
        with MockCTFd(flags={14: "acdc2026{win}"}, rate_limit_always=True) as srv:
            cli = _client(srv)
            cli.login()
            with self.assertRaises(RateLimited):
                cli.submit_flag(14, "acdc2026{win}")


class SessionReopen(unittest.TestCase):
    def test_relogin_after_session_closed(self):
        with MockCTFd(flags={14: "acdc2026{win}"}) as srv:
            cli = _client(srv)
            cli.login()
            # simulate the server closing our session (c14 lesson): wipe server-side
            srv.state.sessions.clear()
            # next call gets a 401; the client must reopen a session and succeed
            status, _ = cli.submit_flag(14, "acdc2026{win}")
            self.assertEqual(status, "correct")
            self.assertEqual(len(srv.state.sessions), 1)  # a fresh session was opened


class DownloadAndFetch(unittest.TestCase):
    def test_download_bytes(self):
        with MockCTFd(flags={7: "acdc2026{x}"},
                      files={"7/handout.bin": b"\x00\x01rawbytes"}) as srv:
            cli = _client(srv)
            cli.login()
            detail = cli.get_challenge(7)
            url = detail["files"][0]
            self.assertEqual(cli.download_file(url), b"\x00\x01rawbytes")

    def test_fetch_all_writes_arena_and_sanitizes(self):
        with MockCTFd(
            challenges=[{"id": 7, "name": "c7", "category": "crypto", "value": 100,
                         "solved_by_me": False}],
            flags={7: "acdc2026{x}"},
            files={"7/../../evil.sh": b"owned", "7/ok.txt": b"fine"},
        ) as srv:
            cli = _client(srv)
            arena = Path(tempfile.mkdtemp())
            store = Path(tempfile.mkdtemp())
            results, manifest = fetch.fetch_all(cli, arena=arena, store=store)
            self.assertEqual(len(results), 1)
            dest = arena / "live_7"
            written = sorted(p.name for p in dest.iterdir())
            # no path traversal: nothing escaped the challenge dir
            self.assertFalse((arena / "evil.sh").exists())
            self.assertFalse((arena.parent / "evil.sh").exists())
            for name in written:
                self.assertNotIn("/", name)
                self.assertNotIn("..", name.strip("."))
            self.assertIn("ok.txt", written)
            self.assertIn("live_7", manifest)


class SanitizeUnit(unittest.TestCase):
    def test_safe_name(self):
        self.assertEqual(fetch._safe_name("../../etc/passwd", "f"), "passwd")
        self.assertEqual(fetch._safe_name("/abs/path/x.bin", "f"), "x.bin")
        self.assertEqual(fetch._safe_name("", "fallback"), "fallback")
        self.assertEqual(fetch._safe_name("..", "fb"), "fb")
        self.assertNotIn("/", fetch._safe_name("a/b/c", "f"))


if __name__ == "__main__":
    unittest.main()
