package main

// One end-to-end check against a mocked Datalix API: login, CSRF, KVM
// filtering, security headers. Run: go test ./...

import (
	"encoding/base64"
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
			if r.FormValue("name") != "partner" {
				w.WriteHeader(400)
				json(w, `{"error":"bad affiliate name"}`)
				return
			}
			json(w, `[]`)
		case r.URL.Path == "/user/"+testUID+"/affiliate":
			json(w, `[{"id":"7c1d2e3f-0a5b-4c6d-8e9f-1a2b3c4d5e6f","name":"afflink","servicecount":3,"servicerevenue":"12.34","percent":10}]`)
		case r.Method == "DELETE" && r.URL.Path == "/user/"+testUID+"/affiliate/7c1d2e3f-0a5b-4c6d-8e9f-1a2b3c4d5e6f":
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
					"cron":true,"ddoslog":true,"customisomount":true},
				"product":{"status":"running","hostname":"vm1","node":"node7","location":"Frankfurt",
					"proxmoxid":123,"trafficnotify":1,"uplink":1000,"maxuplink":3000,
					"clusterinfo":{"displayname":"EPYC Cluster"}},
				"service":{"id":"`+testKVM+`","name":"my kvm","price":5.99,"productdisplay":"KVM Server",
					"expire_at":1790000000,"autorenew":1,"autorenewpayment":"0","attacknotify":0}}`)
		case r.Method == "GET" && r.URL.Path == "/service/"+testKVM+"/cron":
			json(w, `[{"id":"c1","displayname":"nightly","action":"backup","expression":"0 4 * * *","nextexecute":"2026-08-02 04:00:00"}]`)
		case r.Method == "POST" && r.URL.Path == "/service/"+testKVM+"/cron":
			if r.FormValue("expression") != "0 5 * * *" || r.FormValue("action") != "backup" {
				w.WriteHeader(400)
				json(w, `{"error":"bad cron"}`)
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
			json(w, `[{"type":"kvmpackage","id":"bbbbbbbb-0000-0000-0000-000000000001","displayname":"KVM S","line":"AMD EPYC","price":4.99,"cores":4,"memory":8192,"disk":163840,"traffic":20,"active":1},
				{"type":"dedicatedpackage","id":"d1","displayname":"DEDI L","price":30,"setup":15,"stock":0,"traffic":30,"diskbase":"2x1TB"}]`)
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
		case r.URL.Path == "/support/ticket/list":
			json(w, `[{"id":4821,"title":"Server unreachable","last_update":1753900000,"created_on":1753800000,
				"status":{"text":"Answered","bgcolor":"lime-600","textcolor":"white"}}]`)
		case r.URL.Path == "/service/list":
			json(w, `[
				{"id":"aaaaaaaa-0000-0000-0000-000000000001","name":"my kvm","price":5.99,"productdisplay":"KVM Server","productid":2,"expire_at":1790000000},
				{"id":"aaaaaaaa-0000-0000-0000-000000000002","name":"null","price":3.99,"productdisplay":"Gameserver","productid":4,"expire_at":1790000000}
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
	if !strings.Contains(body, "Gameserver") ||
		!strings.Contains(body, "https://datalix.de/cp/service/aaaaaaaa-0000-0000-0000-000000000002") {
		t.Fatal("non-KVM service should be in the services grid, linking to the official panel")
	}
	if strings.Contains(body, `href="/server/aaaaaaaa-0000-0000-0000-000000000002"`) {
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

	// orders page: paginated shape decoded, HTML stripped, pager rendered
	resp, err = client.Get(panel.URL + "/orders")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, resp)
	if !strings.Contains(body, "KVM package") || !strings.Contains(body, "Completed") {
		t.Fatal("orders page missing badges")
	}
	if !strings.Contains(body, "Price: 4.95 € · Period: 30 days") {
		t.Fatal("orderInfo HTML not converted to plain text")
	}
	if !strings.Contains(body, "/orders?start=10") || strings.Contains(body, "previous") {
		t.Fatal("pagination wrong: want next link only on first page")
	}

	// invoices page links each invoice to the PDF proxy
	resp, err = client.Get(panel.URL + "/account")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, resp)
	if !strings.Contains(body, `href="/invoice/2001"`) || !strings.Contains(body, "RE-1001") {
		t.Fatal("invoice row not linked to PDF proxy")
	}

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
	resp, err = client.Get(panel.URL + "/transactions")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, resp)
	if !strings.Contains(body, "Top up") || !strings.Contains(body, "5.00") {
		t.Fatal("transactions page missing credit log entry")
	}

	// donations page: stats, link list with delete form, last donations
	resp, err = client.Get(panel.URL + "/donations")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, resp)
	if !strings.Contains(body, "12.50") || !strings.Contains(body, "https://datalix.de/cp/donate/mylink") {
		t.Fatal("donations page missing stats or link row")
	}
	if !strings.Contains(body, "Thanks for the stream") || !strings.Contains(body, "25.00") {
		t.Fatal("donations page missing donation row")
	}
	if !strings.Contains(body, `name="id" value="3f9a1c2e-7b4d-4a1e-9c3f-2b6d8e1f0a55"`) {
		t.Fatal("donations page missing delete form")
	}

	// create + delete round-trip through the API
	sessCSRF2 := findSessionCSRF(t, client, panel.URL)
	resp, err = client.PostForm(panel.URL+"/donations/create", url.Values{
		"csrf": {sessCSRF2}, "name": {"streamlink"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if body = readBody(t, resp); !strings.Contains(body, "Donation link created.") {
		t.Fatal("donation link create did not flash success")
	}
	resp, err = client.PostForm(panel.URL+"/donations/delete", url.Values{
		"csrf": {sessCSRF2}, "id": {"3f9a1c2e-7b4d-4a1e-9c3f-2b6d8e1f0a55"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if body = readBody(t, resp); !strings.Contains(body, "Donation link deleted.") {
		t.Fatal("donation link delete did not flash success")
	}

	// affiliate page: stats, link row with revenue, transaction statuses
	resp, err = client.Get(panel.URL + "/affiliate")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, resp)
	if !strings.Contains(body, "30.25") || !strings.Contains(body, "4.50") {
		t.Fatal("affiliate page missing stats")
	}
	if !strings.Contains(body, "https://datalix.de/a/afflink") || !strings.Contains(body, "12.34") {
		t.Fatal("affiliate page missing link row")
	}
	if !strings.Contains(body, "Being processed") || !strings.Contains(body, "Paid") {
		t.Fatal("affiliate page missing transaction status chips")
	}

	// affiliate create + delete round-trip
	affCSRF := findSessionCSRF(t, client, panel.URL)
	resp, err = client.PostForm(panel.URL+"/affiliate/create", url.Values{
		"csrf": {affCSRF}, "name": {"partner"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if body = readBody(t, resp); !strings.Contains(body, "Affiliate link created.") {
		t.Fatal("affiliate link create did not flash success")
	}
	resp, err = client.PostForm(panel.URL+"/affiliate/delete", url.Values{
		"csrf": {affCSRF}, "id": {"7c1d2e3f-0a5b-4c6d-8e9f-1a2b3c4d5e6f"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if body = readBody(t, resp); !strings.Contains(body, "Affiliate link deleted.") {
		t.Fatal("affiliate link delete did not flash success")
	}

	// top up credit page: method cards, modal, prefilled invoice data
	resp, err = client.Get(panel.URL + "/credit")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, resp)
	if !strings.Contains(body, `data-method="paypal"`) || !strings.Contains(body, `data-method="cryptocurrency-xmr"`) {
		t.Fatal("credit page missing payment method cards")
	}
	if !strings.Contains(body, `src="/static/payment/paypal.png"`) {
		t.Fatal("credit page missing payment method icons")
	}
	if !strings.Contains(body, `id="pay-modal"`) || !strings.Contains(body, `Germany — 19%`) {
		t.Fatal("credit page missing modal or country options")
	}
	if !strings.Contains(body, `value="Max"`) {
		t.Fatal("credit page invoice data not prefilled")
	}

	// top-up round-trip: credit/add → order pay → redirect to provider
	payCSRF := findSessionCSRF(t, client, panel.URL)
	noRedir := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err = noRedir.PostForm(panel.URL+"/credit/topup", url.Values{
		"csrf": {payCSRF}, "method": {"paypal"}, "amount": {"25"},
		"tos": {"1"}, "privacy": {"1"}, "norefund": {"1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, resp)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("topup: want 303, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://pay.example/checkout/777" {
		t.Fatalf("topup redirect: got %q", loc)
	}

	// topup without the consents → bounced back with an error, no API call
	resp, err = noRedir.PostForm(panel.URL+"/credit/topup", url.Values{
		"csrf": {payCSRF}, "method": {"paypal"}, "amount": {"25"},
	})
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, resp)
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/credit?err=") {
		t.Fatalf("topup without consents should flash an error, got %q", loc)
	}

	// purchase by invoice page: stats, unpaid positions, own invoices, pay options
	resp, err = client.Get(panel.URL + "/paybyinvoice")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, resp)
	if !strings.Contains(body, "4.99") || !strings.Contains(body, "Active") {
		t.Fatal("paybyinvoice page missing limit/status stats")
	}
	if !strings.Contains(body, "KVM Server") || !strings.Contains(body, `data-transaction="31337"`) {
		t.Fatal("paybyinvoice page missing unpaid position row")
	}
	if !strings.Contains(body, "june bundle") || !strings.Contains(body, "Pay with credit") {
		t.Fatal("paybyinvoice page missing own invoices or pay options")
	}
	if strings.Count(body, `class="btn pbi-edit"`) != 1 {
		t.Fatal("edit button should exist for the custom invoice only, not for default")
	}

	// create + rename + reassign + pay-with-credit flash flows
	pbiCSRF := findSessionCSRF(t, client, panel.URL)
	for _, tc := range []struct{ path, msg string; form url.Values }{
		{"/paybyinvoice/create", "Own invoice created.", url.Values{"name": {"custom"}}},
		{"/paybyinvoice/rename", "Own invoice renamed.", url.Values{"id": {"9e8d7c6b-5a49-4321-8765-fedcba098765"}, "name": {"renamed"}}},
		{"/paybyinvoice/reassign", "Transaction reassigned.", url.Values{"invoice": {"default"}, "transaction": {"31337"}}},
		{"/paybyinvoice/pay", "Invoice paid with credit.", url.Values{"id": {"default"}, "paymentmethod": {"credit"}}},
	} {
		tc.form.Set("csrf", pbiCSRF)
		resp, err = client.PostForm(panel.URL+tc.path, tc.form)
		if err != nil {
			t.Fatal(err)
		}
		if body = readBody(t, resp); !strings.Contains(body, tc.msg) {
			t.Fatalf("%s did not flash %q", tc.path, tc.msg)
		}
	}

	// paying with a provider forwards to the checkout URL
	resp, err = noRedir.PostForm(panel.URL+"/paybyinvoice/pay", url.Values{
		"csrf": {pbiCSRF}, "id": {"default"}, "paymentmethod": {"paypal"},
	})
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, resp)
	if loc := resp.Header.Get("Location"); loc != "https://pay.example/checkout/888" {
		t.Fatalf("invoice pay redirect: got %q", loc)
	}

	// server page: scheduled tasks tab renders the cron list with edit forms
	resp, err = client.Get(panel.URL + "/server/" + testKVM + "?tab=tasks")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, resp)
	if !strings.Contains(body, `value="nightly"`) || !strings.Contains(body, `value="0 4 * * *"`) {
		t.Fatal("tasks tab missing cron entry")
	}

	// creating a scheduled task round-trips through the API
	srvCSRF := findSessionCSRF(t, client, panel.URL)
	resp, err = client.PostForm(panel.URL+"/server/"+testKVM+"/cron", url.Values{
		"csrf": {srvCSRF}, "name": {"weekly"}, "expression": {"0 5 * * *"}, "action": {"backup"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if body = readBody(t, resp); !strings.Contains(body, "Scheduled task created.") {
		t.Fatal("cron create did not flash success")
	}

	// ddos tab: incident row + pagination
	resp, err = client.Get(panel.URL + "/server/" + testKVM + "?tab=ddos")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, resp)
	if !strings.Contains(body, "UDP flood") || !strings.Contains(body, "showing 0–10 of 25") {
		t.Fatal("ddos tab missing incidents or pagination")
	}

	// protection status change hits the (undocumented) prot/status endpoint
	resp, err = client.PostForm(panel.URL+"/server/"+testKVM+"/protstatus", url.Values{
		"csrf": {srvCSRF}, "ip": {"1.2.3.4"}, "status": {"permanent"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if body = readBody(t, resp); !strings.Contains(body, "DDoS protection changed") {
		t.Fatal("prot status change did not flash success")
	}

	// order catalog: kvm orderable, dedicated shown as sold out / external
	resp, err = client.Get(panel.URL + "/order")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, resp)
	if !strings.Contains(body, "KVM S") || !strings.Contains(body, `href="/order/bbbbbbbb-0000-0000-0000-000000000001"`) {
		t.Fatal("order page missing orderable KVM package")
	}
	if !strings.Contains(body, "DEDI L") || !strings.Contains(body, "sold out") {
		t.Fatal("order page missing dedicated package row")
	}

	// order config page renders the OS list
	resp, err = client.Get(panel.URL + "/order/bbbbbbbb-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if body = readBody(t, resp); !strings.Contains(body, "Debian 12") {
		t.Fatal("order config missing OS list")
	}

	// placing the order forwards to the payment provider
	ordCSRF := findSessionCSRF(t, client, panel.URL)
	resp, err = noRedir.PostForm(panel.URL+"/order/bbbbbbbb-0000-0000-0000-000000000001", url.Values{
		"csrf": {ordCSRF}, "os": {"cccccccc-0000-0000-0000-000000000001"}, "ipcount": {"1"},
		"paymentmethod": {"paypal"}, "credit": {"1"}, "tos": {"1"}, "privacy": {"1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, resp)
	if loc := resp.Header.Get("Location"); loc != "https://pay.example/checkout/555" {
		t.Fatalf("kvm order redirect: got %q", loc)
	}

	// access manager: code + both lists render, create/accept round-trip
	resp, err = client.Get(panel.URL + "/access")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, resp)
	if !strings.Contains(body, "ACCESS-CODE-99") {
		t.Fatal("access code not rendered")
	}
	if !strings.Contains(body, "buddy") || !strings.Contains(body, "team access") {
		t.Fatal("access lists not rendered")
	}
	if !strings.Contains(body, "Start server") || !strings.Contains(body, `value="start" checked`) {
		t.Fatal("permission tree / granted perms not rendered")
	}
	accCSRF := findSessionCSRF(t, client, panel.URL)
	resp, err = client.PostForm(panel.URL+"/access/create", url.Values{
		"csrf": {accCSRF}, "service": {"aaaaaaaa-0000-0000-0000-000000000001"},
		"key": {"AKEY123"}, "name": {"mate"}, "perm": {"start", "showLoginData"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if body = readBody(t, resp); !strings.Contains(body, "Invitation sent") {
		t.Fatal("access create did not flash success")
	}
	resp, err = client.PostForm(panel.URL+"/access/accept", url.Values{
		"csrf": {accCSRF}, "id": {"eeeeeeee-0000-0000-0000-000000000002"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if body = readBody(t, resp); !strings.Contains(body, "Access request accepted") {
		t.Fatal("access accept did not flash success")
	}

	// emaillog renders the sent-mail list
	resp, err = client.Get(panel.URL + "/emaillog")
	if err != nil {
		t.Fatal(err)
	}
	if body = readBody(t, resp); !strings.Contains(body, "Order #1234 confirmed") {
		t.Fatal("emaillog missing entries")
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
