package main

// One end-to-end check against a mocked Datalix API: login, CSRF, KVM
// filtering, security headers. Run: go test ./...

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

const (
	testKey = "testkey_abcdef123456"
	testUID = "11111111-1111-1111-1111-111111111111"
)

func mockDatalix(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	json := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}
	authed := func(r *http.Request) bool { return r.URL.Query().Get("token") == testKey }
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			w.WriteHeader(401)
			json(w, `{"error":"Invalid session"}`)
			return
		}
		switch {
		case r.URL.Path == "/user/apikey/"+testKey:
			json(w, `{"id":"k1","userInfo":{"id":"`+testUID+`"}}`)
		case r.URL.Path == "/user/"+testUID+"/dashboard":
			json(w, `{"credit":25.5,"supportpin":"483920","emailverified":1,
				"activity":[{"text":"E-Mail <span class=\"text-gray-900\">Log-in notification</span> sent","time":"2 days ago"}]}`)
		case r.URL.Path == "/support/ticket/list":
			json(w, `[{"id":4821,"title":"Server unreachable","last_update":1753900000,"created_on":1753800000,
				"status":{"text":"Answered","bgcolor":"lime-600","textcolor":"white"}}]`)
		case r.URL.Path == "/service/list":
			json(w, `[
				{"id":"aaaaaaaa-0000-0000-0000-000000000001","name":"my kvm","price":5.99,"productdisplay":"KVM Server","expire_at":1790000000},
				{"id":"aaaaaaaa-0000-0000-0000-000000000002","name":"null","price":3.99,"productdisplay":"Gameserver","expire_at":1790000000}
			]`)
		default:
			t.Logf("mock: unhandled %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
			json(w, `{"error":"not found"}`)
		}
	})
	return httptest.NewServer(mux)
}

func TestLoginFlowAndSecurity(t *testing.T) {
	mock := mockDatalix(t)
	defer mock.Close()
	apiBase = mock.URL

	initTemplates()
	panel := httptest.NewServer(newMux())
	defer panel.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// unauthenticated → redirected to /login
	resp, err := client.Get(panel.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(resp.Request.URL.Path, "/login") {
		t.Fatalf("expected redirect to /login, got %s", resp.Request.URL)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("missing CSP, got %q", csp)
	}
	body := readBody(t, resp)
	csrf := regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(body)
	if csrf == nil {
		t.Fatal("no csrf field on login page")
	}

	// login with auto-detected user id
	resp, err = client.PostForm(panel.URL+"/login", url.Values{
		"csrf": {csrf[1]}, "apikey": {testKey},
	})
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, resp)
	if resp.Request.URL.Path != "/" {
		t.Fatalf("login did not land on overview: %s (body: %.200s)", resp.Request.URL, body)
	}

	// KVM service rendered, non-KVM kept out of the managed grid
	if !strings.Contains(body, "my kvm") {
		t.Fatalf("overview missing KVM server; body:\n%s", body)
	}
	if !strings.Contains(body, "Other services") || !strings.Contains(body, "Gameserver") {
		t.Fatal("non-KVM service should be listed under other services")
	}
	if strings.Contains(body, "/server/aaaaaaaa-0000-0000-0000-000000000002") {
		t.Fatal("non-KVM service must not link to server management")
	}
	if !strings.Contains(body, "483920") {
		t.Fatal("support pin not rendered")
	}
	// activity HTML from the API must be stripped, not shown raw or rendered
	if !strings.Contains(body, "E-Mail Log-in notification sent") || strings.Contains(body, "text-gray-900") {
		t.Fatal("activity feed HTML not stripped")
	}
	if strings.Contains(body, testKey) {
		t.Fatal("API key leaked into HTML")
	}

	// service overview page: KVM row manageable, non-KVM row not
	resp, err = client.Get(panel.URL + "/services")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, resp)
	if !strings.Contains(body, "my kvm") || !strings.Contains(body, "Gameserver") {
		t.Fatal("services page missing rows")
	}
	if !strings.Contains(body, "/server/aaaaaaaa-0000-0000-0000-000000000001") {
		t.Fatal("services page missing manage link for KVM")
	}
	if strings.Contains(body, `href="/server/aaaaaaaa-0000-0000-0000-000000000002"`) {
		t.Fatal("non-KVM service must not be manageable on services page")
	}

	// ticket overview renders the undocumented ticket-list endpoint
	resp, err = client.Get(panel.URL + "/tickets")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, resp)
	if !strings.Contains(body, "Server unreachable") || !strings.Contains(body, "4821") {
		t.Fatal("ticket overview missing ticket row")
	}
	if !strings.Contains(body, "Answered") {
		t.Fatal("ticket status badge missing")
	}

	// POST without CSRF → rejected
	resp, err = client.PostForm(panel.URL+"/logout", url.Values{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("logout without csrf: want 403, got %d", resp.StatusCode)
	}
	readBody(t, resp)

	// cross-origin POST → rejected even with valid CSRF
	sessCSRF := findSessionCSRF(t, client, panel.URL)
	req, _ := http.NewRequest("POST", panel.URL+"/logout",
		strings.NewReader("csrf="+sessCSRF))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin POST: want 403, got %d", resp.StatusCode)
	}
	readBody(t, resp)

	// proper logout works and kills the session
	resp, err = client.PostForm(panel.URL+"/logout", url.Values{"csrf": {sessCSRF}})
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, resp)
	resp, err = client.Get(panel.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, resp)
	if !strings.HasSuffix(resp.Request.URL.Path, "/login") {
		t.Fatal("session survived logout")
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return string(b)
}

func findSessionCSRF(t *testing.T, client *http.Client, base string) string {
	t.Helper()
	resp, err := client.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	m := regexp.MustCompile(`name="csrf" value="([a-f0-9]{64})"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no csrf token on authed page")
	}
	return m[1]
}
