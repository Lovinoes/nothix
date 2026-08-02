package main

// One end-to-end check against a mocked Datalix API: login, CSRF, KVM
// filtering, security headers. Run: go test ./...

import (
	"encoding/base64"
	"flag"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// demoMode serves the panel against the mock API for manual clicking:
//
//	go test -C src -run TestDemoServer -timeout 0 -demo
//
// then log in at http://127.0.0.1:8481 with testKey.
var demoMode = flag.Bool("demo", false, "serve the demo panel on :8481 instead of testing")

func TestDemoServer(t *testing.T) {
	if !*demoMode {
		t.Skip("run with -demo to serve the demo panel")
	}
	mock := mockDatalix(t)
	defer mock.Close()
	apiBase = mock.URL
	initTemplates()
	log.Printf("demo panel on http://127.0.0.1:8481 — log in with API key %q", testKey)
	log.Fatal(http.ListenAndServe("127.0.0.1:8481", newMux()))
}

const (
	testKey = "testkey_abcdef123456"
	testUID = "11111111-1111-1111-1111-111111111111"
	testKVM = "aaaaaaaa-0000-0000-0000-000000000001"
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
			json(w, `{"id":"k1","userInfo":{"id":"`+testUID+`","accesskey":"ACCESS-CODE-99"}}`)
		case r.URL.Path == "/user/"+testUID+"/dashboard":
			json(w, `{"credit":25.5,"supportpin":"483920","emailverified":1,
				"activity":[{"text":"E-Mail <span class=\"text-gray-900\">Log-in notification</span> sent","time":"2 days ago"}]}`)
		case r.URL.Path == "/user/"+testUID+"/orders":
			json(w, `{"data":[{"id":9911,"status":1,"type":"kvmServerPacket",
				"orderInfo":"Price: 4.95 €<br>Period: 30 days","created_on":1750684800}],
				"pageInfo":{"last":0,"stepsize":10,"total":11}}`)
		case r.URL.Path == "/user/"+testUID+"/invoice/list":
			json(w, `[{"id":"2001","invoiceNumber":"RE-1001","create":"23.06.2026","sum":19.99,"status":1}]`)
		case r.URL.Path == "/user/"+testUID+"/invoice/2001":
			// Sevdesk-style envelope: PDF as base64 inside JSON
			json(w, `{"objects":{"filename":"RE-1001.pdf","base64Encoded":true,"content":"`+
				base64.StdEncoding.EncodeToString([]byte("%PDF-1.4 fake invoice"))+`"}}`)
		case r.URL.Path == "/user/"+testUID+"/credit/log":
			json(w, `[{"change":"5.00","type":"+","display":"Top up","created_on":1750684800}]`)
		case r.URL.Path == "/user/"+testUID+"/credit/donation/info":
			json(w, `{"linkcount":1,"totalmoney":12.5}`)
		case r.URL.Path == "/user/"+testUID+"/credit/donation/link/list":
			json(w, `[{"id":"3f9a1c2e-7b4d-4a1e-9c3f-2b6d8e1f0a55","name":"mylink","created_on":1718064000}]`)
		case r.URL.Path == "/user/"+testUID+"/credit/donation/list":
			json(w, `[{"donationlink":"3f9a1c2e-7b4d-4a1e-9c3f-2b6d8e1f0a55","link":"mylink","reason":"Thanks for the stream","amount":25.0,"created_on":1718000000}]`)
		case r.Method == "POST" && r.URL.Path == "/user/"+testUID+"/credit/donation/link":
			if r.FormValue("link") != "streamlink" {
				w.WriteHeader(400)
				json(w, `{"error":"bad link name"}`)
				return
			}
			json(w, `[]`)
		case r.Method == "DELETE" && r.URL.Path == "/user/"+testUID+"/credit/donation/link/3f9a1c2e-7b4d-4a1e-9c3f-2b6d8e1f0a55":
			json(w, `[]`)
		case r.URL.Path == "/user/"+testUID+"/affiliate/info":
			json(w, `{"linkcount":2,"totalmoney":30.25,"moneyhold":4.5}`)
		case r.URL.Path == "/user/"+testUID+"/affiliate/list":
			json(w, `[{"link":"afflink","amount":2.5,"status":0,"created_on":1718000000},
				{"link":"afflink","amount":3.5,"status":1,"created_on":1718000500}]`)
		case r.Method == "POST" && r.URL.Path == "/user/"+testUID+"/affiliate":
			// csrf is the panel's own field and must never be forwarded
			if r.FormValue("name") != "partner" || r.FormValue("csrf") != "" {
				w.WriteHeader(400)
				json(w, `{"error":"bad affiliate name"}`)
				return
			}
			json(w, `[]`)
		case r.URL.Path == "/user/"+testUID+"/affiliate":
			json(w, `[{"id":"7c1d2e3f-0a5b-4c6d-8e9f-1a2b3c4d5e6f","name":"afflink","servicecount":3,"servicerevenue":"12.34","percent":10}]`)
		case r.Method == "DELETE" && r.URL.Path == "/user/"+testUID+"/affiliate/7c1d2e3f-0a5b-4c6d-8e9f-1a2b3c4d5e6f":
			if r.ContentLength != 0 { // a DELETE must not carry a body
				w.WriteHeader(400)
				json(w, `{"error":"unexpected body on delete"}`)
				return
			}
			json(w, `[]`)
		case r.URL.Path == "/user/"+testUID+"/countrys":
			json(w, `[{"id":"c-de","displayname":"Germany","vatamount":"19","ewr":1},
				{"id":"c-world","displayname":"Rest of the World","vatamount":"0","ewr":0}]`)
		case r.Method == "GET" && r.URL.Path == "/user/"+testUID+"/invoicedata":
			json(w, `{"firstname":"Max","lastname":"Muster","street":"Foo 1","zip":"12345","city":"Berlin","company":"","country":"c-de"}`)
		case r.Method == "POST" && r.URL.Path == "/user/"+testUID+"/credit/add":
			if r.FormValue("amount") != "25" || r.FormValue("tax") != "c-de" {
				w.WriteHeader(400)
				json(w, `{"error":"bad credit add"}`)
				return
			}
			json(w, `{"id":"ord-777"}`)
		case r.Method == "POST" && r.URL.Path == "/order/ord-777/pay":
			if r.FormValue("paymentMethod") != "paypal" {
				w.WriteHeader(400)
				json(w, `{"error":"bad method"}`)
				return
			}
			json(w, `{"url":"https://pay.example/checkout/777"}`)
		case r.URL.Path == "/user/"+testUID+"/credit/paybyinvoice/info":
			json(w, `{"limit":4.99,"status":1,"used":2}`)
		case r.URL.Path == "/user/"+testUID+"/credit/log/unpaid":
			json(w, `[{"id":31337,"type":"-","change":3.5,"display":"KVM Server","additionalData":"june","invoice":"default","invoicedisplayname":"default","created_on":1718000000}]`)
		case r.Method == "POST" && r.URL.Path == "/user/"+testUID+"/credit/paybyinvoice/transaction":
			json(w, `[]`)
		case r.Method == "POST" && r.URL.Path == "/user/"+testUID+"/credit/paybyinvoice/default/pay":
			if r.FormValue("paymentmethod") == "credit" {
				json(w, `[]`)
				return
			}
			json(w, `{"id":"ord-888"}`)
		case r.Method == "POST" && r.URL.Path == "/user/"+testUID+"/credit/paybyinvoice":
			json(w, `[]`)
		case r.Method == "POST" && r.URL.Path == "/user/"+testUID+"/credit/paybyinvoice/9e8d7c6b-5a49-4321-8765-fedcba098765":
			json(w, `[]`)
		case r.URL.Path == "/user/"+testUID+"/credit/paybyinvoice/list":
			json(w, `[{"id":"default","name":"default","total":3.5},
				{"id":"9e8d7c6b-5a49-4321-8765-fedcba098765","name":"june bundle","total":0}]`)
		case r.URL.Path == "/payment/paymentmethods":
			json(w, `[{"method":"paypal","display":"PayPal"},{"method":"creditcard","display":"CreditCard"}]`)
		case r.Method == "POST" && r.URL.Path == "/order/ord-888/pay":
			json(w, `{"url":"https://pay.example/checkout/888"}`)
		case r.URL.Path == "/service/"+testKVM:
			json(w, `{"display":{"ip":true,"hardware":true,"traffic":true,"backup":true,"livedata":true,
					"cron":true,"ddoslog":true,"customisomount":true,"actionbuttons":true,"logindata":true,
					"renew":true,"rescue":true,"passwordreset":true,"sshkeys":true},
				"product":{"status":"running","hostname":"vm1","node":"node7","location":"Frankfurt",
					"proxmoxid":123,"trafficnotify":1,"uplink":1000,"maxuplink":3000,
					"user":"root","password":"rootpw","ostype":"linux",
					"clusterinfo":{"displayname":"EPYC Cluster"}},
				"service":{"id":"`+testKVM+`","name":"my kvm","price":5.99,"productdisplay":"KVM Server",
					"productid":2,"expire_at":1790000000,"autorenew":1,"autorenewpayment":"0","attacknotify":0,
					"addons":true}}`)
		case r.URL.Path == "/service/"+testKVM+"/hardware":
			json(w, `{"cores":4,"memory":8192,"disk":163840,"uplink":1000,"traffic":20,
				"cputype":"AMD EPYC 7443P","hostname":"vm1","storagetype":"NVMe",
				"ddosprotection":"Advanced","tpm":1,"uefi":0}`)
		case r.URL.Path == "/service/"+testKVM+"/sshkeys":
			json(w, `[{"id":"dddddddd-0000-0000-0000-000000000001","displayname":"laptop","key":"ssh-ed25519 AAAAtest user@host"}]`)
		case r.URL.Path == "/service/"+testKVM+"/addons":
			json(w, `[{"id":"eeeeeeee-0000-0000-0000-000000000001","name":"Traffic reset","price":2.00,"deletable":1}]`)
		case r.URL.Path == "/service/"+testKVM+"/addons/list":
			json(w, `[{"type":"ram","name":"Extra RAM","price":1.50,"once":0}]`)
		case r.Method == "POST" && r.URL.Path == "/service/"+testKVM+"/addon/order":
			if r.FormValue("addon") != "ram" || r.FormValue("amount") != "2" ||
				r.FormValue("paymentmethod") != "paypal" || r.FormValue("tax") != "c-de" {
				w.WriteHeader(400)
				json(w, `{"error":"bad addon order"}`)
				return
			}
			json(w, `{"id":"ord-addon"}`)
		case r.Method == "GET" && r.URL.Path == "/service/"+testKVM+"/cron":
			json(w, `[{"id":"c1","displayname":"nightly","action":"backup","expression":"0 4 * * *","nextexecute":"2026-08-02 04:00:00"}]`)
		case r.Method == "POST" && r.URL.Path == "/service/"+testKVM+"/cron":
			if r.FormValue("expression") != "0 5 * * *" || r.FormValue("action") != "backup" {
				w.WriteHeader(400)
				json(w, `{"error":"bad cron"}`)
				return
			}
			json(w, `[]`)
		case r.Method == "GET" && r.URL.Path == "/service/"+testKVM+"/ip":
			json(w, `{"ipv4":[{"ip":"1.2.3.4","gw":"1.2.3.1","netmask":"255.255.255.0","rdns":"v123.example.net","note":"","protstatus":"dynamic"}],
				"ipv6":[{"firstip":"2a01:db8::1","gw":"fe80::1","subnet":"2a01:db8::/64","netmask":"64"}],
				"ipv6adresslist":[{"ip":"2a01:db8::10","rdns":"mail.example.net","note":""}]}`)
		case r.Method == "POST" && r.URL.Path == "/service/"+testKVM+"/ip/1.2.3.4/rdns":
			if r.FormValue("rdns") == "" {
				w.WriteHeader(400)
				json(w, `{"error":"bad rdns"}`)
				return
			}
			json(w, `[]`)
		case r.URL.Path == "/service/"+testKVM+"/incidents":
			json(w, `{"data":[{"ip":"1.2.3.4","method":"UDP flood","created_on":1718000000}],
				"pageInfo":{"last":0,"stepsize":10,"total":25}}`)
		case r.Method == "POST" && r.URL.Path == "/service/"+testKVM+"/prot/status":
			if r.FormValue("ip") != "1.2.3.4" || r.FormValue("status") != "permanent" {
				w.WriteHeader(400)
				json(w, `{"error":"bad prot status"}`)
				return
			}
			json(w, `[]`)
		case r.URL.Path == "/reseller/packet/list":
			json(w, `[{"type":"kvmpackage","id":"bbbbbbbb-0000-0000-0000-000000000001","displayname":"KVM S","line":"AMD EPYC","price":4.99,"cores":4,"memory":8192,"disk":163840,"traffic":20,"active":1}]`)
		case r.URL.Path == "/kvmserver/packet/bbbbbbbb-0000-0000-0000-000000000001":
			json(w, `{"id":"bbbbbbbb-0000-0000-0000-000000000001","displayname":"KVM S","line":"AMD EPYC","cores":4,"memory":8192,"disk":163840,"uplink":1000,"ipv4":1,"price":4.99,"traffic":20}`)
		case r.URL.Path == "/kvmserver/packet/bbbbbbbb-0000-0000-0000-000000000001/os":
			json(w, `[{"id":"cccccccc-0000-0000-0000-000000000001","displayname":"Debian 12"}]`)
		case r.Method == "POST" && r.URL.Path == "/order/kvmserver/bbbbbbbb-0000-0000-0000-000000000001":
			if r.FormValue("os") != "cccccccc-0000-0000-0000-000000000001" || r.FormValue("ipcount") != "1" {
				w.WriteHeader(400)
				json(w, `{"error":"bad kvm order"}`)
				return
			}
			json(w, `{"id":"ord-555"}`)
		case r.Method == "POST" && r.URL.Path == "/order/ord-555/pay":
			json(w, `{"url":"https://pay.example/checkout/555"}`)
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002":
			json(w, `{"service":{"id":"aaaaaaaa-0000-0000-0000-000000000002","productdisplay":"Gameserver","productid":4}}`)
		case r.Method == "POST" && r.URL.Path == "/order/ord-addon/pay":
			json(w, `{"url":"https://pay.example/checkout/addon"}`)
		case r.Method == "GET" && r.URL.Path == "/service/"+testKVM+"/upgrade":
			json(w, `[{"id":"up-m","displayname":"KVM M","monthlyprice":9.99,"onetimepayment":4.50,"cores":6,"memory":16384,"disk":245760}]`)
		case r.Method == "POST" && r.URL.Path == "/service/"+testKVM+"/upgrade":
			if r.FormValue("package") != "up-m" || r.FormValue("tax") != "c-de" {
				w.WriteHeader(400)
				json(w, `{"error":"bad upgrade"}`)
				return
			}
			json(w, `{"id":"ord-upg"}`)
		case r.Method == "POST" && r.URL.Path == "/order/ord-upg/pay":
			json(w, `{"url":"https://pay.example/checkout/upg"}`)
		case r.URL.Path == "/support/ticket/4821":
			json(w, `{"id":4821,"title":"Server unreachable","created_on":1753800000,
				"status":{"text":"Answered","bgcolor":"lime-600"},
				"answers":[
					{"content":"It broke<br>please help","created_on":1753800000,"admin":0,"internal":0,"author":{"username":"me"}},
					{"content":"secret note","created_on":1753800001,"admin":1,"internal":1,"author":{"username":"staff"}},
					{"content":"We are on it","created_on":1753900000,"admin":1,"internal":0,"author":{"username":"Datalix Support"}}]}`)
		case r.Method == "POST" && r.URL.Path == "/support/ticket/4821/answer":
			if r.FormValue("text") != "thanks!" {
				w.WriteHeader(400)
				json(w, `{"error":"bad answer"}`)
				return
			}
			json(w, `[]`)
		case r.URL.Path == "/support/ticket/list":
			json(w, `[{"id":4821,"title":"Server unreachable","last_update":1753900000,"created_on":1753800000,
				"status":{"text":"Answered","bgcolor":"lime-600"}}]`)
		case r.URL.Path == "/service/list":
			// one service of every product type Datalix sells
			json(w, `[
				{"id":"aaaaaaaa-0000-0000-0000-000000000001","name":"my kvm","price":5.99,"productdisplay":"KVM Server","productid":2,"expire_at":1790000000},
				{"id":"aaaaaaaa-0000-0000-0000-000000000002","name":"null","price":3.99,"productdisplay":"Gameserver","productid":4,"expire_at":1790000000},
				{"id":"aaaaaaaa-0000-0000-0000-000000000003","name":"big iron","price":39.00,"productdisplay":"Dedicated Server","productid":1,"expire_at":1790000000},
				{"id":"aaaaaaaa-0000-0000-0000-000000000004","name":"null","price":1.99,"productdisplay":"Webspace","productid":3,"expire_at":1790000000},
				{"id":"aaaaaaaa-0000-0000-0000-000000000005","name":"my cloud","price":4.49,"productdisplay":"Nextcloud","productid":5,"expire_at":1790000000},
				{"id":"aaaaaaaa-0000-0000-0000-000000000006","name":"null","price":89.00,"productdisplay":"Colocation","productid":6,"expire_at":1790000000},
				{"id":"aaaaaaaa-0000-0000-0000-000000000007","name":"backup bucket","price":2.99,"productdisplay":"Object Storage","productid":7,"expire_at":1790000000},
				{"id":"aaaaaaaa-0000-0000-0000-000000000008","name":"null","price":9.00,"productdisplay":"IP Subnet","productid":8,"expire_at":1790000000}
			]`)
		case r.URL.Path == "/user/access/info":
			json(w, `{"2":[{"name":"start","header":"Start server","sub":[{"name":"showLoginData","header":"Show login data"}]},{"name":"restart","header":"Restart server"}],"3":[]}`)
		case r.URL.Path == "/user/"+testUID+"/access/list":
			json(w, `[{"id":"eeeeeeee-0000-0000-0000-000000000001","serviceid":"`+testKVM+`","status":2,
				"created_on":"2026-06-23 12:34:56","name":"buddy","productid":2,"entrys":[{"perm":"start"}]}]`)
		case r.URL.Path == "/user/"+testUID+"/access/list/request":
			json(w, `[{"id":"eeeeeeee-0000-0000-0000-000000000002","serviceid":"`+testKVM+`","status":1,
				"created_on":1750636800,"name":"team access","productid":2,"entrys":[]}]`)
		case r.Method == "POST" && r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000001/access":
			if r.FormValue("key") != "AKEY123" || len(r.MultipartForm.Value["permissions[]"]) != 2 {
				w.WriteHeader(400)
				json(w, `{"error":"bad access create"}`)
				return
			}
			json(w, `[]`)
		case r.Method == "POST" && r.URL.Path == "/user/"+testUID+"/access/eeeeeeee-0000-0000-0000-000000000002/accept":
			json(w, `[]`)
		case r.URL.Path == "/user/"+testUID+"/email/log":
			json(w, `[{"id":"ffffffff-0000-0000-0000-000000000001","header":"Order #1234 confirmed","template":"Order","created_on":1718000000,"send":1}]`)
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/traffic"):
			json(w, `{"max":20,"current":3.5,"history":{
				"last30days":[{"date":"2026-07-31","in":1024,"out":512}],
				"months":[{"date":"2026-06","in":2048,"out":1024}]}}`)
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/status"):
			json(w, `{"status":"running"}`)
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/livedata"):
			json(w, `{"cpu":0.42,"mem":3221225472,"netin":52428800000,"netout":10485760000}`)
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
	readBody(t, resp)
	csrf := findSessionCSRF(t, client, panel.URL)

	// login with auto-detected user id
	resp, err = client.PostForm(panel.URL+"/login", url.Values{
		"csrf": {csrf}, "apikey": {testKey},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if resp.Request.URL.Path != "/" {
		t.Fatalf("login did not land on overview: %s (body: %.200s)", resp.Request.URL, body)
	}

	// a second visitor is a second session: signing in here signs in nobody else
	otherJar, _ := cookiejar.New(nil)
	stranger := &http.Client{Jar: otherJar}
	resp, err = stranger.Get(panel.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if b := readBody(t, resp); !strings.HasSuffix(resp.Request.URL.Path, "/login") || strings.Contains(b, "483920") {
		t.Fatal("a second visitor inherited the first one's session")
	}
	resp, err = stranger.Get(panel.URL + "/api/proxy/user/" + testUID + "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("proxy served a session-less visitor: %d", resp.StatusCode)
	}

	// one token is enough: the session CSRF never rotates
	sessCSRF := findSessionCSRF(t, client, panel.URL)
	get := func(path string) string {
		t.Helper()
		resp, err := client.Get(panel.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		return readBody(t, resp)
	}
	flash := func(path, msg string, form url.Values) {
		t.Helper()
		form.Set("csrf", sessCSRF)
		resp, err := client.PostForm(panel.URL+path, form)
		if err != nil {
			t.Fatal(err)
		}
		if b := readBody(t, resp); !strings.Contains(b, msg) {
			t.Fatalf("%s did not flash %q", path, msg)
		}
	}
	want := func(body string, subs ...string) {
		t.Helper()
		for _, s := range subs {
			if !strings.Contains(body, s) {
				t.Fatalf("page missing %q", s)
			}
		}
	}

	// KVM service rendered, non-KVM kept out of the managed grid
	if !strings.Contains(body, "my kvm") {
		t.Fatalf("overview missing KVM server; body:\n%s", body)
	}
	// non-KVM cards open the official-panel popup instead of /server/…
	want(body, "Gameserver", `data-ext="https://datalix.eu/cp/service/aaaaaaaa-0000-0000-0000-000000000002"`)
	if strings.Contains(body, `href="/server/aaaaaaaa-0000-0000-0000-000000000002"`) {
		t.Fatal("non-KVM service links to the internal server page")
	}
	want(body, "Dedicated Server", "Webspace", "Nextcloud", "Colocation", "Object Storage", "IP Subnet", "ext-modal")
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
	body = get("/services")
	want(body, "my kvm", "Gameserver", "/server/aaaaaaaa-0000-0000-0000-000000000001",
		`data-ext="https://datalix.eu/cp/service/aaaaaaaa-0000-0000-0000-000000000002"`)

	// ticket overview renders the undocumented ticket-list endpoint
	body = get("/tickets")
	want(body, "Server unreachable", "4821", "Answered")

	// orders page: paginated shape decoded, HTML stripped, pager rendered
	body = get("/orders")
	want(body, "KVM package", "Completed", "Price: 4.95 € · Period: 30 days", "/orders?start=10")
	if strings.Contains(body, "previous") {
		t.Fatal("pagination wrong: want next link only on first page")
	}

	// invoices page links each invoice to the PDF proxy
	body = get("/account")
	want(body, `href="/invoice/2001"`, "RE-1001")

	// the proxy unwraps the base64 JSON envelope into a real PDF
	resp, err = client.Get(panel.URL + "/invoice/2001")
	if err != nil {
		t.Fatal(err)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/pdf" {
		t.Fatalf("invoice proxy content-type: want application/pdf, got %q", ct)
	}
	if body = readBody(t, resp); !strings.HasPrefix(body, "%PDF") {
		t.Fatalf("invoice proxy did not return a PDF: %.60q", body)
	}

	// transactions page renders the credit log
	body = get("/transactions")
	want(body, "Top up", "5.00")

	// donations page: stats, link list with delete form, last donations
	body = get("/donations")
	want(body, "12.50", "https://datalix.de/cp/donate/mylink")
	want(body, "Thanks for the stream", "25.00")
	if !strings.Contains(body, `name="id" value="3f9a1c2e-7b4d-4a1e-9c3f-2b6d8e1f0a55"`) {
		t.Fatal("donations page missing delete form")
	}

	// create + delete round-trip through the API
	flash("/donations/create", "Donation link created.", url.Values{"name": {"streamlink"}})
	flash("/donations/delete", "Donation link deleted.", url.Values{"id": {"3f9a1c2e-7b4d-4a1e-9c3f-2b6d8e1f0a55"}})

	// affiliate page: stats, link row with revenue, transaction statuses
	body = get("/affiliate")
	want(body, "30.25", "4.50")
	want(body, "https://datalix.de/a/afflink", "12.34")
	want(body, "Being processed", "Paid")

	// affiliate create + delete round-trip
	flash("/affiliate/create", "Affiliate link created.", url.Values{"name": {"partner"}})
	flash("/affiliate/delete", "Affiliate link deleted.", url.Values{"id": {"7c1d2e3f-0a5b-4c6d-8e9f-1a2b3c4d5e6f"}})

	// settings general tab renders the shared invoice-data partial
	want(get("/settings"), `id="pay-country"`, `Germany — 19%`, `value="Max"`)

	// top up credit page: method cards, modal, prefilled invoice data
	body = get("/credit")
	want(body, `data-method="paypal"`, `data-method="cryptocurrency-xmr"`, `src="/static/payment/paypal.png"`)
	want(body, `id="pay-modal"`, `Germany — 19%`, `value="Max"`)

	// top-up round-trip: credit/add → order pay → redirect to provider
	noRedir := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	postLoc := func(path string, form url.Values) string {
		t.Helper()
		form.Set("csrf", sessCSRF)
		resp, err := noRedir.PostForm(panel.URL+path, form)
		if err != nil {
			t.Fatal(err)
		}
		readBody(t, resp)
		return resp.Header.Get("Location")
	}
	if loc := postLoc("/credit/topup", url.Values{"method": {"paypal"}, "amount": {"25"},
		"tos": {"1"}, "privacy": {"1"}, "norefund": {"1"}}); loc != "https://pay.example/checkout/777" {
		t.Fatalf("topup redirect: got %q", loc)
	}

	// topup without the consents → bounced back with an error, no API call.
	// The text rides on the session: a flash in the URL could be mailed to a
	// victim as a link and would render in the panel's own alert box.
	if loc := postLoc("/credit/topup", url.Values{"method": {"paypal"}, "amount": {"25"}}); loc != "/credit" {
		t.Fatalf("topup without consents should bounce back to /credit, got %q", loc)
	}
	want(get("/credit"), "Please accept the terms, the privacy policy")
	if b := get("/credit"); strings.Contains(b, "Please accept the terms") {
		t.Fatal("flash message survived being read once")
	}
	for _, u := range []string{"/credit?err=INJECTED", "/credit?msg=INJECTED"} {
		if strings.Contains(get(u), "INJECTED") {
			t.Fatalf("%s echoed attacker-supplied flash text", u)
		}
	}
	// the login page is the one that matters: unauthenticated, and the banner
	// sits directly above the API key field. Use a session-less client, an
	// authenticated one gets redirected away before the page renders.
	for _, q := range []string{"?err=INJECTED", "?err=rejected"} {
		resp, err = stranger.Get(panel.URL + "/login" + q)
		if err != nil {
			t.Fatal(err)
		}
		b := readBody(t, resp)
		if strings.Contains(b, "INJECTED") {
			t.Fatal("login page echoed attacker-supplied flash text")
		}
		if q == "?err=rejected" && !strings.Contains(b, "API key was rejected") {
			t.Fatal("the rejected sentinel no longer renders its message")
		}
	}

	// purchase by invoice page: stats, unpaid positions, own invoices, pay options
	body = get("/paybyinvoice")
	want(body, "4.99", "Active")
	want(body, "KVM Server", `data-transaction="31337"`)
	want(body, "june bundle", "Pay with credit")
	if strings.Count(body, `data-dlg="pbi-edit-modal"`) != 1 {
		t.Fatal("edit button should exist for the custom invoice only, not for default")
	}

	// create + rename + reassign + pay-with-credit flash flows
	flash("/paybyinvoice/create", "Own invoice created.", url.Values{"name": {"custom"}})
	flash("/paybyinvoice/rename", "Own invoice renamed.", url.Values{"id": {"9e8d7c6b-5a49-4321-8765-fedcba098765"}, "name": {"renamed"}})
	flash("/paybyinvoice/reassign", "Transaction reassigned.", url.Values{"invoice": {"default"}, "transaction": {"31337"}})
	flash("/paybyinvoice/pay", "Invoice paid with credit.", url.Values{"id": {"default"}, "paymentmethod": {"credit"}})

	// paying with a provider forwards to the checkout URL
	if loc := postLoc("/paybyinvoice/pay", url.Values{"id": {"default"}, "paymentmethod": {"paypal"}}); loc != "https://pay.example/checkout/888" {
		t.Fatalf("invoice pay redirect: got %q", loc)
	}

	// server page: scheduled tasks tab renders the cron list with edit forms
	body = get("/server/" + testKVM + "?tab=tasks")
	want(body, `value="nightly"`, `value="0 4 * * *"`)

	// creating a scheduled task round-trips through the API
	flash("/server/"+testKVM+"/cron", "Scheduled task created.", url.Values{
		"name": {"weekly"}, "expression": {"0 5 * * *"}, "action": {"backup"},
	})

	// hardware tab decodes straight into Hardware (no per-product fallback)
	body = get("/server/" + testKVM + "?tab=hardware")
	want(body, "AMD EPYC 7443P", "NVMe", "Advanced", "EPYC Cluster", "node7")

	// traffic tab: both bar charts render through the shared "bars" partial
	body = get("/server/" + testKVM + "?tab=traffic")
	want(body, "Last 30 days", "Month view", `title="2026-07-31 — in 1.00 GB · out 0.50 GB"`,
		`title="2026-06 — in 2.00 GB · out 1.00 GB"`, `<i class="in" style="height:100%">`)

	// ddos tab: incident row + pagination
	body = get("/server/" + testKVM + "?tab=ddos")
	want(body, "UDP flood", "showing 0–10 of 25")

	// protection status change hits the (undocumented) prot/status endpoint
	flash("/server/"+testKVM+"/protstatus", "DDoS protection changed", url.Values{
		"ip": {"1.2.3.4"}, "status": {"permanent"},
	})

	// order catalog: kvm packages only, orderable
	want(get("/order"), "KVM S", `href="/order/bbbbbbbb-0000-0000-0000-000000000001"`)

	// order config page renders the OS list
	want(get("/order/bbbbbbbb-0000-0000-0000-000000000001"), "Debian 12")

	// placing the order forwards to the payment provider
	if loc := postLoc("/order/bbbbbbbb-0000-0000-0000-000000000001", url.Values{
		"os": {"cccccccc-0000-0000-0000-000000000001"}, "ipcount": {"1"},
		"paymentmethod": {"paypal"}, "credit": {"1"}, "tos": {"1"}, "privacy": {"1"},
	}); loc != "https://pay.example/checkout/555" {
		t.Fatalf("kvm order redirect: got %q", loc)
	}

	// access manager: code + both lists render, create/accept round-trip
	body = get("/access")
	want(body, "ACCESS-CODE-99", "buddy", "team access", "Start server", `value="start" checked`)
	// webspace (productid 3) cannot be shared and must be missing from the create dropdown
	if strings.Contains(body, `value="aaaaaaaa-0000-0000-0000-000000000004"`) {
		t.Fatal("webspace service must not be offered in the access create dialog")
	}
	if !strings.Contains(body, `value="aaaaaaaa-0000-0000-0000-000000000007"`) {
		t.Fatal("object storage service missing from the access create dialog")
	}
	flash("/access/create", "Invitation sent", url.Values{
		"service": {"aaaaaaaa-0000-0000-0000-000000000001"},
		"key":     {"AKEY123"}, "name": {"mate"}, "perm": {"start", "showLoginData"},
	})
	flash("/access/accept", "Access request accepted", url.Values{"id": {"eeeeeeee-0000-0000-0000-000000000002"}})

	// emaillog renders the sent-mail list
	want(get("/emaillog"), "Order #1234 confirmed")

	// non-KVM services bounce to the services list with an official-panel notice
	body = get("/server/aaaaaaaa-0000-0000-0000-000000000002")
	want(body, "official Datalix panel")
	if strings.Contains(body, `value="start"`) {
		t.Fatal("non-KVM service rendered a management page")
	}

	// IPv4 rDNS reset computes the default in-addr.arpa entry server-side
	flash("/server/"+testKVM+"/rdns", "rDNS updated", url.Values{"ip": {"1.2.3.4"}, "rdns": {""}, "reset": {"1"}})

	// KVM addons tab + order checkout redirect; KVM upgrade checkout redirect
	body = get("/server/" + testKVM + "?tab=addons")
	want(body, "Traffic reset", "Extra RAM")
	if loc := postLoc("/server/"+testKVM+"/addon/order", url.Values{
		"addon": {"ram"}, "amount": {"2"}, "method": {"paypal"}, "credit": {"1"},
	}); loc != "https://pay.example/checkout/addon" {
		t.Fatalf("addon order redirect: got %q", loc)
	}
	want(get("/server/"+testKVM+"?tab=billing"), "KVM M — 9.99")
	if loc := postLoc("/server/"+testKVM+"/upgrade", url.Values{
		"package": {"up-m"}, "method": {"paypal"}, "credit": {"1"},
	}); loc != "https://pay.example/checkout/upg" {
		t.Fatalf("upgrade order redirect: got %q", loc)
	}

	// service SSH keys tab (linux KVM) renders
	body = get("/server/" + testKVM + "?tab=sshkeys")
	want(body, "laptop", "ssh-ed25519")

	// ticket thread renders, internal notes stay hidden, answering round-trips
	body = get("/tickets/4821")
	want(body, "It broke\nplease help", "We are on it")
	if strings.Contains(body, "secret note") {
		t.Fatal("internal ticket note must not be shown")
	}
	flash("/tickets/4821/answer", "Answer sent", url.Values{"text": {"thanks!"}})

	// ── /api/proxy passthrough ──
	proxy := func(path string) (int, string, string) {
		t.Helper()
		resp, err := client.Get(panel.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, resp.Header.Get("Content-Type"), readBody(t, resp)
	}

	// the token JS needs for proxy writes is on the page
	want(get("/"), `<meta name="csrf" content="`+sessCSRF+`">`)

	// GET is forwarded and the upstream JSON comes back untouched
	code, ctype, pbody := proxy("/api/proxy/user/" + testUID + "/dashboard")
	if code != http.StatusOK || !strings.Contains(ctype, "application/json") {
		t.Fatalf("proxy GET: %d %q", code, ctype)
	}
	want(pbody, `"supportpin":"483920"`)

	// a caller-supplied token must not shadow the session's own
	if code, _, _ = proxy("/api/proxy/user/" + testUID + "/dashboard?token=evil"); code != http.StatusOK {
		t.Fatalf("caller-supplied token reached the API: %d", code)
	}

	// upstream status codes pass through instead of collapsing to 200
	if code, _, _ = proxy("/api/proxy/nope/nothing"); code != http.StatusNotFound {
		t.Fatalf("proxy swallowed the upstream 404: %d", code)
	}

	// traversal never reaches the API, encoded or not
	if code, _, _ = proxy("/api/proxy/user/%2e%2e/secret"); code != http.StatusBadRequest {
		t.Fatalf("proxy accepted traversal: %d", code)
	}

	// writes need the CSRF token, exactly like a form POST
	resp, err = client.PostForm(panel.URL+"/api/proxy/user/"+testUID+"/affiliate",
		url.Values{"name": {"partner"}})
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("proxy POST without csrf: want 403, got %d", resp.StatusCode)
	}
	resp, err = client.PostForm(panel.URL+"/api/proxy/user/"+testUID+"/affiliate",
		url.Values{"csrf": {sessCSRF}, "name": {"partner"}})
	if err != nil {
		t.Fatal(err)
	}
	if b := readBody(t, resp); resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy POST with csrf: want 200, got %d (%s)", resp.StatusCode, b)
	}

	send := func(method, path string, body io.Reader, hdr map[string]string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(method, panel.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, readBody(t, resp)
	}
	aff := "/api/proxy/user/" + testUID + "/affiliate"
	affLink := aff + "/7c1d2e3f-0a5b-4c6d-8e9f-1a2b3c4d5e6f"
	tokenHdr := map[string]string{"X-CSRF-Token": sessCSRF}

	// DELETE has no body to put a token in, so it carries the header instead,
	// and must reach the API without a body attached
	if code, b := send("DELETE", affLink, nil, tokenHdr); code != http.StatusOK {
		t.Fatalf("proxy DELETE with header token: want 200, got %d (%s)", code, b)
	}
	if code, _ = send("DELETE", affLink, nil, nil); code != http.StatusForbidden {
		t.Fatalf("proxy DELETE without token: want 403, got %d", code)
	}

	// a body the proxy cannot re-encode is refused, not forwarded field-less
	if code, _ = send("POST", aff, strings.NewReader("--x--\r\n"), map[string]string{
		"X-CSRF-Token": sessCSRF,
		"Content-Type": "multipart/form-data; boundary=x",
	}); code != http.StatusUnsupportedMediaType {
		t.Fatalf("proxy accepted a body it cannot forward: %d", code)
	}

	// methods outside the allowlist never reach the API
	if code, _ = send("PUT", aff, nil, tokenHdr); code != http.StatusMethodNotAllowed {
		t.Fatalf("proxy PUT: want 405, got %d", code)
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

	// the proxy answers a fetch()-shaped 401 instead of redirecting to /login
	if code, _, _ = proxy("/api/proxy/user/" + testUID + "/dashboard"); code != http.StatusUnauthorized {
		t.Fatalf("proxy after logout: want 401, got %d", code)
	}
}

// The login limiter is only worth anything if it counts the real client, so a
// forwarded header must be believed behind our proxy and ignored anywhere else.
func TestClientIP(t *testing.T) {
	for _, c := range []struct{ remote, fwd, want string }{
		{"127.0.0.1:5555", "203.0.113.9", "203.0.113.9"},          // nginx on the same host
		{"127.0.0.1:5555", "1.2.3.4, 203.0.113.9", "203.0.113.9"}, // client-supplied prefix ignored
		{"172.17.0.1:5555", "203.0.113.9", "203.0.113.9"},         // docker bridge
		{"127.0.0.1:5555", "", "127.0.0.1"},
		{"127.0.0.1:5555", "not-an-ip", "127.0.0.1"},
		{"198.51.100.7:5555", "203.0.113.9", "198.51.100.7"}, // exposed directly: header is a lie
	} {
		r := httptest.NewRequest("POST", "/login", nil)
		r.RemoteAddr = c.remote
		if c.fwd != "" {
			r.Header.Set("X-Forwarded-For", c.fwd)
		}
		if got := clientIP(r); got != c.want {
			t.Errorf("clientIP(%s, xff=%q) = %q, want %q", c.remote, c.fwd, got, c.want)
		}
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
