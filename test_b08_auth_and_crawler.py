import re
import unittest
from unittest.mock import MagicMock, call, patch
import requests

from core.authenticator import AutoAuthenticator, AuthResult
from core.crawler import WebCrawler, CrawlResult, _normalize_url


class TestB08AutoLoginAndCrawler(unittest.TestCase):
    # -----------------------------------------------------------------------
    # AUD-22: Auto-login reports success on failed logins
    # -----------------------------------------------------------------------
    def test_aud22_get_sets_cookie_and_post_returns_200_invalid_password_fails(self):
        """AUD-22: A server whose GET sets a cookie and whose POST returns 200 'Invalid email or password' -> success == False."""
        session = MagicMock(spec=requests.Session)
        session.headers = {}
        # Pre-login, session has no cookies
        session.cookies = requests.cookies.RequestsCookieJar()

        # GET on /login sets a cookie (e.g. csrftoken or session)
        get_resp = MagicMock(spec=requests.Response)
        get_resp.status_code = 200
        get_resp.headers = {"Content-Type": "text/html"}
        get_resp.text = """
        <form action="/login" method="POST">
            <input type="text" name="email" />
            <input type="password" name="password" />
        </form>
        """

        def mock_get(url, *args, **kwargs):
            session.cookies.set("csrftoken", "csrf_cookie_from_get")
            return get_resp

        session.get.side_effect = mock_get

        # POST returns 200 with "Invalid email or password" and no new cookies
        post_resp = MagicMock(spec=requests.Response)
        post_resp.status_code = 200
        post_resp.url = "http://localhost:3000/login"
        post_resp.text = "<html><body>Invalid email or password</body></html>"
        post_resp.cookies = requests.cookies.RequestsCookieJar()
        post_resp.json.side_effect = ValueError("Not JSON")

        session.post.return_value = post_resp

        auth = AutoAuthenticator(
            base_url="http://localhost:3000",
            username="admin@example.com",
            password="wrong_password",
            login_url="/login",
            session=session
        )

        result = auth.authenticate()
        self.assertFalse(result.success, f"Expected success=False when POST returns 200 with invalid credentials, got {result.success}")

    def test_aud22_juice_shop_nested_token_and_verification(self):
        """AUD-22: Juice-Shop-shaped server (token in authentication.token, root returns 401 without token and 200 with it) -> success == True, token captured."""
        session = MagicMock(spec=requests.Session)
        session.headers = {}
        session.cookies = requests.cookies.RequestsCookieJar()

        # Juice shop login endpoint is JSON API: empty POST returns 401
        def mock_post(url, *args, **kwargs):
            json_body = kwargs.get("json", {})
            if json_body == {}:
                resp = MagicMock(spec=requests.Response)
                resp.status_code = 401
                resp.text = '{"error": "Empty credentials"}'
                return resp
            # Real Juice Shop requires email key; returns 401 "Invalid email or password." otherwise
            if "email" not in json_body:
                resp = MagicMock(spec=requests.Response)
                resp.status_code = 401
                resp.text = "Invalid email or password."
                return resp
            # Valid credentials POST: returns nested token {"authentication": {"token": "jwt_token_12345"}}
            resp = MagicMock(spec=requests.Response)
            resp.status_code = 200
            resp.url = "http://localhost:3000/rest/user/login"
            resp.text = '{"authentication": {"token": "jwt_token_juice_shop_12345"}}'
            resp.cookies = requests.cookies.RequestsCookieJar()
            resp.json.return_value = {
                "authentication": {
                    "token": "jwt_token_juice_shop_12345",
                    "bid": 1
                }
            }
            return resp

        # Anonymous GET to root returns 401. GET with Bearer token returns 200.
        def mock_get(url, *args, **kwargs):
            headers = kwargs.get("headers", {})
            auth_hdr = headers.get("Authorization", "") or session.headers.get("Authorization", "")
            resp = MagicMock(spec=requests.Response)
            if "Bearer jwt_token_juice_shop_12345" in auth_hdr:
                resp.status_code = 200
                resp.text = "Welcome to Juice Shop!"
            else:
                resp.status_code = 401
                resp.text = "Unauthorized"
            resp.headers = {"Content-Type": "application/json"}
            return resp

        session.post.side_effect = mock_post
        session.get.side_effect = mock_get

        auth = AutoAuthenticator(
            base_url="http://localhost:3000",
            username="admin@juice-sh.op",
            password="admin123Password!",
            login_url="/rest/user/login",
            session=session
        )

        result = auth.authenticate()
        self.assertTrue(result.success, f"Expected success=True for Juice Shop auth, got {result.success} with message {result.message}")
        self.assertEqual(result.token, "jwt_token_juice_shop_12345")
        self.assertEqual(result.headers.get("Authorization"), "Bearer jwt_token_juice_shop_12345")
        self.assertLessEqual(session.post.call_count, 6)

    def test_aud22_root_200_and_post_rotates_cookie_returns_200_unmatched_records_fails(self):
        """AUD-22: Root returns 200 'Home page', POST rotates sid and returns 200 'Those details don't match our records' -> success == False."""
        session = MagicMock(spec=requests.Session)
        session.headers = {}
        session.cookies = requests.cookies.RequestsCookieJar()

        # GET to root and any GET returns 200 "Home page"
        get_resp = MagicMock(spec=requests.Response)
        get_resp.status_code = 200
        get_resp.url = "http://localhost:3000/"
        get_resp.headers = {"Content-Type": "text/html"}
        get_resp.text = "<html><body>Home page</body></html>"
        session.get.return_value = get_resp

        # POST returns 200 with failure text and sets a new 'sid' cookie
        post_resp = MagicMock(spec=requests.Response)
        post_resp.status_code = 200
        post_resp.url = "http://localhost:3000/login"
        post_resp.text = "<html><body>Those details don't match our records</body></html>"
        post_resp.cookies = requests.cookies.RequestsCookieJar()
        post_resp.cookies.set("sid", "new_rotated_sid_9999")
        post_resp.json.side_effect = ValueError("Not JSON")

        def mock_post(url, *args, **kwargs):
            session.cookies.set("sid", "new_rotated_sid_9999")
            return post_resp

        session.post.side_effect = mock_post

        auth = AutoAuthenticator(
            base_url="http://localhost:3000",
            username="victim@example.com",
            password="wrong_password",
            login_url="/login",
            session=session
        )

        result = auth.authenticate()
        self.assertFalse(result.success, f"Expected success=False when POST fails even with rotated cookie, got {result.success}")

    # -----------------------------------------------------------------------
    # AUD-23: Credential spraying across 14 paths -> account lockout
    # -----------------------------------------------------------------------
    def test_aud23_server_with_200_html_without_forms_sends_at_most_6_credential_posts(self):
        """AUD-23: Against a server where every path returns 200 HTML without a form, at most 6 credential POSTs are sent."""
        session = MagicMock(spec=requests.Session)
        session.headers = {}
        session.cookies = requests.cookies.RequestsCookieJar()

        # Every GET returns 200 HTML without any form
        get_resp = MagicMock(spec=requests.Response)
        get_resp.status_code = 200
        get_resp.headers = {"Content-Type": "text/html"}
        get_resp.text = "<html><body><h1>Welcome to our SPA</h1><p>No forms here</p></body></html>"
        session.get.return_value = get_resp

        # Any POST also returns 200 HTML
        post_resp = MagicMock(spec=requests.Response)
        post_resp.status_code = 200
        post_resp.headers = {"Content-Type": "text/html"}
        post_resp.text = "<html><body>Static HTML</body></html>"
        post_resp.url = "http://localhost:3000/login"
        post_resp.json.side_effect = ValueError("Not JSON")
        session.post.return_value = post_resp

        auth = AutoAuthenticator(
            base_url="http://localhost:3000",
            username="target_user",
            password="target_password",
            session=session
        )

        auth.authenticate()

        # Count POST requests that contained credentials (username or password)
        credential_post_count = 0
        for call_item in session.post.call_args_list:
            args, kwargs = call_item
            data = kwargs.get("data") or {}
            json_data = kwargs.get("json") or {}
            payload_str = str(data) + str(json_data)
            if "target_user" in payload_str or "target_password" in payload_str:
                credential_post_count += 1

        self.assertLessEqual(
            credential_post_count,
            6,
            f"Expected at most 6 credential POSTs, but sent {credential_post_count}"
        )

    def test_aud23_stops_at_first_endpoint_that_clearly_rejects_credentials(self):
        """AUD-23: Stops spraying at the first endpoint that clearly rejects the credentials."""
        session = MagicMock(spec=requests.Session)
        session.headers = {}
        session.cookies = requests.cookies.RequestsCookieJar()

        # First path /login returns form with password
        def mock_get(url, *args, **kwargs):
            resp = MagicMock(spec=requests.Response)
            resp.status_code = 200
            resp.headers = {"Content-Type": "text/html"}
            resp.text = '<form action="/login" method="POST"><input type="password" name="password"></form>'
            return resp

        # POST to /login clearly rejects credentials
        def mock_post(url, *args, **kwargs):
            resp = MagicMock(spec=requests.Response)
            resp.status_code = 401
            resp.text = "Invalid username or password"
            resp.json.side_effect = ValueError("Not JSON")
            return resp

        session.get.side_effect = mock_get
        session.post.side_effect = mock_post

        auth = AutoAuthenticator(
            base_url="http://localhost:3000",
            username="victim_user",
            password="victim_password",
            session=session
        )

        auth.authenticate()

        # Since /login clearly rejected credentials, it must NOT continue spraying other paths
        credential_post_count = 0
        for call_item in session.post.call_args_list:
            args, kwargs = call_item
            payload_str = str(kwargs.get("data", {})) + str(kwargs.get("json", {}))
            if "victim_user" in payload_str or "victim_password" in payload_str:
                credential_post_count += 1

        self.assertEqual(
            credential_post_count,
            1,
            f"Expected to stop immediately after clear rejection (1 POST), but sent {credential_post_count}"
        )

    def test_aud23_all_paths_get_200_json_and_empty_post_200_sends_zero_credential_posts(self):
        """AUD-23: When every path's GET returns 200 {'status':'ok'} and empty POST returns 200, zero credential POSTs are sent."""
        session = MagicMock(spec=requests.Session)
        session.headers = {}
        session.cookies = requests.cookies.RequestsCookieJar()

        get_resp = MagicMock(spec=requests.Response)
        get_resp.status_code = 200
        get_resp.headers = {"Content-Type": "application/json"}
        get_resp.text = '{"status": "ok"}'
        session.get.return_value = get_resp

        post_resp = MagicMock(spec=requests.Response)
        post_resp.status_code = 200
        post_resp.headers = {"Content-Type": "application/json"}
        post_resp.text = '{"status": "ok"}'
        post_resp.json.return_value = {"status": "ok"}
        session.post.return_value = post_resp

        # Auto-discovery with no explicit login_url
        auth = AutoAuthenticator(
            base_url="http://localhost:3000",
            username="admin@example.com",
            password="secret_password",
            session=session
        )

        auth.authenticate()

        # Count POST requests containing credentials
        credential_posts = 0
        for call_item in session.post.call_args_list:
            args, kwargs = call_item
            payload_str = str(kwargs.get("data", {})) + str(kwargs.get("json", {}))
            if "admin@example.com" in payload_str or "secret_password" in payload_str:
                credential_posts += 1

        self.assertEqual(credential_posts, 0, f"Expected 0 credential POSTs when empty probe returns 200, got {credential_posts}")

    def test_aud23_email_field_sent_first_when_username_contains_at(self):
        """AUD-23: When username contains @, email payload is sent first; stops on success."""
        session = MagicMock(spec=requests.Session)
        session.headers = {}
        session.cookies = requests.cookies.RequestsCookieJar()

        # Probe returns 401 to trigger JSON auth
        def mock_post(url, *args, **kwargs):
            json_body = kwargs.get("json", {})
            if json_body == {}:
                resp = MagicMock(spec=requests.Response)
                resp.status_code = 401
                resp.text = '{"error": "Empty body"}'
                return resp
            # If body has email key, return 200 with token
            if "email" in json_body:
                resp = MagicMock(spec=requests.Response)
                resp.status_code = 200
                resp.url = url
                resp.text = '{"token": "eyJhbGciOiJIUzI1NiJ9.user_token_abc"}'
                resp.cookies = requests.cookies.RequestsCookieJar()
                resp.json.return_value = {"token": "eyJhbGciOiJIUzI1NiJ9.user_token_abc"}
                return resp
            # Otherwise return 401 rejection
            resp = MagicMock(spec=requests.Response)
            resp.status_code = 401
            resp.text = "Invalid email or password."
            return resp

        # Anonymous verify returns 401, authenticated returns 200
        def mock_get(url, *args, **kwargs):
            headers = kwargs.get("headers", {})
            auth_h = headers.get("Authorization", "") or session.headers.get("Authorization", "")
            resp = MagicMock(spec=requests.Response)
            resp.headers = {"Content-Type": "application/json"}
            if "Bearer eyJhbGciOiJIUzI1NiJ9.user_token_abc" in auth_h:
                resp.status_code = 200
                resp.text = '{"status": "ok", "user": "logged_in"}'
            else:
                resp.status_code = 401
                resp.text = "Unauthorized"
            return resp

        session.post.side_effect = mock_post
        session.get.side_effect = mock_get

        auth = AutoAuthenticator(
            base_url="http://localhost:3000",
            username="testuser@domain.com",
            password="securePassword99!",
            login_url="/api/login",
            session=session
        )

        result = auth.authenticate()
        self.assertTrue(result.success, f"Expected success=True, got {result.success}: {result.message}")
        self.assertEqual(result.token, "eyJhbGciOiJIUzI1NiJ9.user_token_abc")
        self.assertLessEqual(session.post.call_count, 6)
        # Ensure the first non-empty payload sent had 'email'
        first_credential_call = None
        for call_item in session.post.call_args_list:
            json_data = call_item[1].get("json", {})
            if json_data != {}:
                first_credential_call = json_data
                break
        self.assertIsNotNone(first_credential_call)
        self.assertIn("email", first_credential_call)

    # -----------------------------------------------------------------------
    # AUD-24: Crawler follows logout/destructive links and leaves scope on redirect
    # -----------------------------------------------------------------------
    def test_aud24_crawler_never_requests_logout_or_delete_links(self):
        """AUD-24: For a page linking /logout and /delete?id=1, neither is ever requested."""
        crawler = WebCrawler(mock_mode=False, max_pages=10, max_depth=2)

        # Mock the session.get
        requested_urls = []

        html_page = """
        <html>
        <body>
            <a href="/dashboard">Dashboard</a>
            <a href="/logout">Logout</a>
            <a href="/delete?id=1">Delete Account</a>
            <form action="/destroy" method="POST">
                <input type="hidden" name="action" value="wipe" />
            </form>
            <a href="/settings">Settings</a>
        </body>
        </html>
        """

        def mock_crawl_get(url, *args, **kwargs):
            requested_urls.append(url)
            resp = MagicMock(spec=requests.Response)
            resp.status_code = 200
            resp.url = url
            resp.headers = {"content-type": "text/html"}
            resp.text = html_page if url == "http://localhost:3000/" else "<html><body>Subpage</body></html>"
            return resp

        crawler._session.get = MagicMock(side_effect=mock_crawl_get)

        result = crawler.crawl("http://localhost:3000")

        # Verify neither /logout, /delete, nor /destroy was requested
        for req_url in requested_urls:
            self.assertNotIn("logout", req_url.lower(), f"Crawler must not request logout URL: {req_url}")
            self.assertNotIn("delete", req_url.lower(), f"Crawler must not request delete URL: {req_url}")
            self.assertNotIn("destroy", req_url.lower(), f"Crawler must not request destroy URL: {req_url}")

        # Verify neither was stored as an endpoint to attack
        for ep in result.endpoints + result.forms:
            self.assertNotIn("logout", ep.path.lower(), f"Endpoint list must not contain logout: {ep.path}")
            self.assertNotIn("delete", ep.path.lower(), f"Endpoint list must not contain delete: {ep.path}")
            self.assertNotIn("destroy", ep.path.lower(), f"Endpoint list must not contain destroy: {ep.path}")

    def test_aud24_crawler_discards_off_origin_redirect(self):
        """AUD-24: Discard response if resp.url left the origin (scheme + host + port)."""
        crawler = WebCrawler(mock_mode=False, max_pages=5, max_depth=2)

        # First request to target redirects to off-origin URL
        resp_off_origin = MagicMock(spec=requests.Response)
        resp_off_origin.status_code = 200
        resp_off_origin.url = "http://evil-tracker.com/login"
        resp_off_origin.headers = {"content-type": "text/html"}
        resp_off_origin.text = '<html><body><a href="/evil-page">Evil</a></body></html>'

        crawler._session.get = MagicMock(return_value=resp_off_origin)

        result = crawler.crawl("http://localhost:3000")

        # Result should not contain endpoints from the off-origin page
        self.assertEqual(len(result.endpoints), 0, "Off-origin redirected page endpoints must be discarded")
        self.assertEqual(result.pages_visited, 0, "Off-origin page must not be counted as visited")

    def test_aud24_configurable_deny_pattern(self):
        """AUD-24: Custom deny pattern is honored by crawler."""
        custom_pattern = r"admin|secret|logout"
        crawler = WebCrawler(mock_mode=False, deny_pattern=custom_pattern)

        requested_urls = []

        html = """
        <html><body>
            <a href="/public">Public</a>
            <a href="/admin/panel">Admin</a>
            <a href="/secret/data">Secret</a>
        </body></html>
        """

        def mock_crawl_get(url, *args, **kwargs):
            requested_urls.append(url)
            resp = MagicMock(spec=requests.Response)
            resp.status_code = 200
            resp.url = url
            resp.headers = {"content-type": "text/html"}
            resp.text = html if url == "http://localhost:3000/" else "<html><body>Public Page</body></html>"
            return resp

        crawler._session.get = MagicMock(side_effect=mock_crawl_get)
        result = crawler.crawl("http://localhost:3000")

        for req_url in requested_urls:
            self.assertNotIn("admin", req_url.lower())
            self.assertNotIn("secret", req_url.lower())

    def test_aud24_crawler_allows_target_domain_containing_deny_words(self):
        """AUD-24: Target domain containing deny words like 'remove' or 'delete' is not blocked; crawl visits pages."""
        crawler = WebCrawler(mock_mode=False, max_pages=5, max_depth=2)

        requested_urls = []
        html = """
        <html><body>
            <a href="/dashboard">Dashboard</a>
            <a href="/delete-user">Delete User</a>
        </body></html>
        """

        def mock_crawl_get(url, *args, **kwargs):
            requested_urls.append(url)
            resp = MagicMock(spec=requests.Response)
            resp.status_code = 200
            resp.url = url
            resp.headers = {"content-type": "text/html"}
            resp.text = html if url.rstrip("/") == "http://remove-me.lab:8000" else "<html><body>Dashboard</body></html>"
            return resp

        crawler._session.get = MagicMock(side_effect=mock_crawl_get)
        result = crawler.crawl("http://remove-me.lab:8000")

        self.assertIn("http://remove-me.lab:8000", requested_urls)
        self.assertIn("http://remove-me.lab:8000/dashboard", requested_urls)
        # /delete-user must be denied
        for u in requested_urls:
            self.assertNotIn("delete-user", u)

    def test_aud24_crawler_discards_redirect_chain_hitting_denied_url(self):
        """AUD-24: A redirect chain landing on or passing through /logout is discarded."""
        crawler = WebCrawler(mock_mode=False, max_pages=5, max_depth=2)

        # Redirect response that lands on /logout
        redirect_hist = MagicMock(spec=requests.Response)
        redirect_hist.url = "http://localhost:3000/link"

        resp = MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.url = "http://localhost:3000/logout"
        resp.headers = {"content-type": "text/html"}
        resp.text = "<html><body>Logged out</body></html>"
        resp.history = [redirect_hist]

        crawler._session.get = MagicMock(return_value=resp)
        result = crawler.crawl("http://localhost:3000")

        # Must discard
        self.assertEqual(len(result.endpoints), 0)


if __name__ == "__main__":
    unittest.main()
