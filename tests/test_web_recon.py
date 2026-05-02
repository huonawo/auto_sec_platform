import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from modules.webscan.web_recon import build_web_context, run_full_recon  # noqa: E402


class FakeResponse:
    def __init__(self, url, status_code=200, headers=None, text="", history=None):
        self.url = url
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.history = history or []


class FakeClient:
    def __init__(self):
        self.head_urls = []

    def get(self, url):
        html = """
        <html><head><title>CTF Box</title></head>
        <body>
          <!-- debug: source leak -->
          <form action="/search?q=1" method="get">
            <input type="hidden" name="csrf" value="token123">
            <input name="id">
          </form>
          mysql_fetch_array() warning
          666c61677b6865787d
          eyJhbGciOiJIUzI1NiJ9.e30.signature
          QWxhZGRpbjpvcGVuIHNlc2FtZQ==
        </body></html>
        """
        history = [FakeResponse("http://ctf.test/start", status_code=302, headers={"Location": "/final"})]
        return FakeResponse(
            "http://ctf.test/final?id=1&next=/admin",
            headers={
                "Server": "nginx",
                "X-Powered-By": "PHP/8.2",
                "Set-Cookie": "session=abc; Path=/; HttpOnly",
            },
            text=html,
            history=history,
        )

    def head(self, url):
        self.head_urls.append(url)
        status = 200 if url.endswith("/.git/HEAD") else 404
        return FakeResponse(url, status_code=status, headers={"Content-Length": "12"})


class WebReconTest(unittest.TestCase):
    def test_extracts_structured_context_from_html_and_headers(self):
        html = """
        <html>
          <head>
            <title>Training Portal</title>
            <script src="/static/app.js"></script>
          </head>
          <body>
            <!-- flag hint: check robots -->
            <a href="/admin">Admin</a>
            <form action="/login" method="post">
              <input type="hidden" name="csrf" value="abc123">
              <input name="username">
            </form>
            QWxhZGRpbjpvcGVuIHNlc2FtZQ==
          </body>
        </html>
        """
        headers = {
            "Content-Type": "text/html",
            "Set-Cookie": "session=abc; Path=/; HttpOnly",
            "Server": "nginx",
        }

        context = build_web_context(
            target="http://ctf.example",
            final_url="http://ctf.example/index",
            status_code=200,
            headers=headers,
            body=html,
        )

        self.assertEqual(context["target"], "http://ctf.example")
        self.assertEqual(context["final_url"], "http://ctf.example/index")
        self.assertEqual(context["status_code"], 200)
        self.assertEqual(context["title"], "Training Portal")
        self.assertIn({"name": "session", "value": "abc"}, context["cookies"])
        self.assertIn("http://ctf.example/admin", context["links"])
        self.assertIn("http://ctf.example/static/app.js", context["scripts"])
        self.assertEqual(context["comments"], ["flag hint: check robots"])
        self.assertEqual(context["forms"][0]["action"], "http://ctf.example/login")
        self.assertIn({"name": "csrf", "value": "abc123"}, context["forms"][0]["hidden_inputs"])
        self.assertTrue(
            any(item["decoded"] == "Aladdin:open sesame" for item in context["interesting_strings"])
        )

    def test_full_recon_collects_required_web_ctf_signals(self):
        client = FakeClient()

        context = run_full_recon("http://ctf.test/start", client=client)

        self.assertEqual(context["title"], "CTF Box")
        self.assertLessEqual(len(context["body"]), 5000)
        self.assertEqual(context["status"], 200)
        self.assertIn("debug: source leak", context["html_comments"])
        self.assertIn({"name": "csrf", "value": "token123"}, context["hidden_fields"])
        self.assertIn({"name": "session", "value": "abc"}, context["cookies"])
        self.assertEqual(context["redirect_chain"], ["http://ctf.test/start"])
        self.assertEqual(context["url_params"]["id"], ["1"])
        self.assertTrue(context["base64_candidates"])
        self.assertIn("666c61677b6865787d", context["hex_candidates"])
        self.assertTrue(context["jwt_candidates"])
        self.assertIn("mysql", context["error_patterns"])
        self.assertEqual(context["server"], "nginx")
        self.assertEqual(context["x-powered-by"], "PHP/8.2")
        self.assertEqual(context["fingerprint"]["server"], "nginx")
        self.assertEqual(context["path_probes"]["/.git/HEAD"]["status"], 200)
        self.assertTrue(all("/" + path.rsplit("/", 1)[-1] in path or path for path in client.head_urls))


if __name__ == "__main__":
    unittest.main()
