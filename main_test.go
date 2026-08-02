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
//	go test -run TestDemoServer -timeout 0 -demo
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
					"cron":true,"ddoslog":true,"customisomount":true,"actionbuttons":true,"logindata":true,
					"renew":true,"rescue":true,"passwordreset":true},
				"product":{"status":"running","hostname":"vm1","node":"node7","location":"Frankfurt",
					"proxmoxid":123,"trafficnotify":1,"uplink":1000,"maxuplink":3000,
					"user":"root","password":"rootpw",
					"clusterinfo":{"displayname":"EPYC Cluster"}},
				"service":{"id":"`+testKVM+`","name":"my kvm","price":5.99,"productdisplay":"KVM Server",
					"productid":2,"expire_at":1790000000,"autorenew":1,"autorenewpayment":"0","attacknotify":0}}`)
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
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002":
			json(w, `{"display":{"backup":true,"livedata":true,"cron":true,"hardware":true,"settings":true,"sshkeys":true,
					"actionbuttons":true,"logindata":true,"renew":true,"files":true},
				"product":{"status":"running","ostype":"linux","modmanager":1,
					"ip":"5.6.7.8","port":25565,
					"version":"v1","versionchange":2,"gameid":"g-mc",
					"sftp":{"user":"gs1","password":"sftppw","ip":"5.6.7.8","port":2022},
					"db":{"user":"db1","password":"dbpw","host":"db.example","port":3306,"db":"gs1db",
						"phpmyadminurl":"https://pma.example"}},
				"service":{"id":"aaaaaaaa-0000-0000-0000-000000000002","name":"null","price":3.99,
					"productdisplay":"Gameserver","productid":4,"expire_at":1790000000,"addons":true}}`)
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/hardware":
			json(w, `{"slots":10,"game":"Minecraft","addons":[{"name":"extra ram","gb":2}]}`)
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/settings":
			json(w, `[{"name":"Max Players","description":"Player slots","env_variable":"MAX_PLAYERS",
				"server_value":"20","default_value":"16","canedit":1}]`)
		case r.Method == "POST" && r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/settings/variable":
			if r.FormValue("variable") != "MAX_PLAYERS" || r.FormValue("value") != "32" {
				w.WriteHeader(400)
				json(w, `{"error":"bad variable"}`)
				return
			}
			json(w, `[]`)
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/sshkeys":
			json(w, `[{"id":"dddddddd-0000-0000-0000-000000000001","displayname":"laptop","key":"ssh-ed25519 AAAAtest user@host"}]`)
		case r.Method == "POST" && r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/files":
			if r.FormValue("directory") != "/" {
				json(w, `[]`)
				return
			}
			json(w, `[{"name":"plugins","is_file":0,"sizedisplay":"-"},
				{"name":"server.properties","is_file":1,"sizedisplay":"1.2 KB","mimetype":"text/plain"},
				{"name":"world.zip","is_file":1,"sizedisplay":"120 MB","mimetype":"application/zip"}]`)
		case r.Method == "GET" && r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/file":
			if r.URL.Query().Get("filepath") != "/server.properties" {
				w.WriteHeader(400)
				json(w, `{"error":"no such file"}`)
				return
			}
			json(w, `{"data":"motd=hello"}`)
		case r.Method == "POST" && r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/file":
			if r.FormValue("file") != "/server.properties" || r.FormValue("data") != "motd=changed" {
				w.WriteHeader(400)
				json(w, `{"error":"bad save"}`)
				return
			}
			json(w, `[]`)
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/file/delete":
			json(w, `[]`)
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/file/unzip":
			json(w, `[]`)
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/file/download":
			json(w, `{"link":"https://dl.example/server.properties"}`)
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/mods":
			json(w, `[{"name":"worldedit","title":"WorldEdit","summary":"In-game map editor","thumbnail":""}]`)
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/mod/list":
			if r.FormValue("query") != "essentials" {
				json(w, `[]`)
				return
			}
			json(w, `[{"name":"essentialsx","title":"EssentialsX","summary":"Core server commands","thumbnail":""}]`)
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/mod/add":
			if r.FormValue("mod") != "essentialsx" {
				w.WriteHeader(400)
				json(w, `{"error":"bad mod"}`)
				return
			}
			json(w, `[]`)
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/mod/delete":
			json(w, `[]`)
		case r.Method == "GET" && r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/version":
			json(w, `[{"id":"v1","version":"1.20"},{"id":"v2","version":"1.21"}]`)
		case r.Method == "POST" && r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/version":
			if r.FormValue("version") != "v2" {
				w.WriteHeader(400)
				json(w, `{"error":"bad version"}`)
				return
			}
			json(w, `[]`)
		case r.Method == "GET" && r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/gamechanger":
			json(w, `[{"id":"g-mc","displayname":"Minecraft","versions":[{"id":"v1","version":"1.20"},{"id":"v2","version":"1.21"}]},
				{"id":"g-rust","displayname":"Rust","versions":[{"id":"r1","version":"latest"}]}]`)
		case r.Method == "POST" && r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/gamechanger":
			if r.FormValue("game") != "g-rust" || r.FormValue("version") != "r1" {
				w.WriteHeader(400)
				json(w, `{"error":"bad game"}`)
				return
			}
			json(w, `[]`)
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/networkdata":
			json(w, `[{"ip":"5.6.7.8","port":25565,"default":1},{"ip":"5.6.7.8","port":25570,"default":0}]`)
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/extraport":
			json(w, `[]`)
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/sftp/reset",
			r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/db/reset":
			json(w, `[]`)
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/addons":
			json(w, `[{"id":"eeeeeeee-0000-0000-0000-000000000001","name":"Traffic reset","price":2.00,"deletable":1}]`)
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/addons/list":
			json(w, `[{"type":"ram","name":"Extra RAM","price":1.50,"max":4,"once":0}]`)
		case r.Method == "POST" && r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000002/addon/order":
			if r.FormValue("addon") != "ram" || r.FormValue("amount") != "2" ||
				r.FormValue("paymentmethod") != "paypal" || r.FormValue("tax") != "c-de" {
				w.WriteHeader(400)
				json(w, `{"error":"bad addon order"}`)
				return
			}
			json(w, `{"id":"ord-addon"}`)
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
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000007":
			json(w, `{"display":{"hardware":true,"bucketlist":true,"keylist":true,"renew":true},
				"product":{"status":"running"},
				"service":{"id":"aaaaaaaa-0000-0000-0000-000000000007","name":"backup bucket","price":2.99,
					"productdisplay":"Object Storage","productid":7,"expire_at":1790000000}}`)
		case r.Method == "POST" && r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000007/buckets":
			if r.FormValue("name") != "my-bucket" {
				w.WriteHeader(400)
				json(w, `{"error":"bad bucket name"}`)
				return
			}
			json(w, `[]`)
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000007/buckets":
			json(w, `[{"name":"backups","size":5300000000,"objects":42}]`)
		case r.URL.Path == "/service/aaaaaaaa-0000-0000-0000-000000000007/keys":
			json(w, `[{"access_key":"AKtest123","secret_key":"SEKRIT456"}]`)
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
	want(body, "Gameserver", `href="/server/aaaaaaaa-0000-0000-0000-000000000002"`)
	want(body, "Dedicated Server", "Webspace", "Nextcloud", "Colocation", "Object Storage", "IP Subnet")
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
	want(body, "my kvm", "Gameserver")
	if !strings.Contains(body, "/server/aaaaaaaa-0000-0000-0000-000000000001") {
		t.Fatal("services page missing manage link for KVM")
	}
	if !strings.Contains(body, `href="/server/aaaaaaaa-0000-0000-0000-000000000002"`) {
		t.Fatal("services page missing manage link for non-KVM service")
	}

	// ticket overview renders the undocumented ticket-list endpoint
	body = get("/tickets")
	want(body, "Server unreachable", "4821")
	if !strings.Contains(body, "Answered") {
		t.Fatal("ticket status badge missing")
	}

	// orders page: paginated shape decoded, HTML stripped, pager rendered
	body = get("/orders")
	want(body, "KVM package", "Completed")
	if !strings.Contains(body, "Price: 4.95 € · Period: 30 days") {
		t.Fatal("orderInfo HTML not converted to plain text")
	}
	if !strings.Contains(body, "/orders?start=10") || strings.Contains(body, "previous") {
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

	// top up credit page: method cards, modal, prefilled invoice data
	body = get("/credit")
	want(body, `data-method="paypal"`, `data-method="cryptocurrency-xmr"`)
	if !strings.Contains(body, `src="/static/payment/paypal.png"`) {
		t.Fatal("credit page missing payment method icons")
	}
	want(body, `id="pay-modal"`, `Germany — 19%`)
	if !strings.Contains(body, `value="Max"`) {
		t.Fatal("credit page invoice data not prefilled")
	}

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
	resp, err = noRedir.PostForm(panel.URL+"/credit/topup", url.Values{
		"csrf": {sessCSRF}, "method": {"paypal"}, "amount": {"25"},
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
		"csrf": {sessCSRF}, "method": {"paypal"}, "amount": {"25"},
	})
	if err != nil {
		t.Fatal(err)
	}
	readBody(t, resp)
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/credit?err=") {
		t.Fatalf("topup without consents should flash an error, got %q", loc)
	}

	// purchase by invoice page: stats, unpaid positions, own invoices, pay options
	body = get("/paybyinvoice")
	want(body, "4.99", "Active")
	want(body, "KVM Server", `data-transaction="31337"`)
	want(body, "june bundle", "Pay with credit")
	if strings.Count(body, `class="btn pbi-edit"`) != 1 {
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

	// ddos tab: incident row + pagination
	body = get("/server/" + testKVM + "?tab=ddos")
	want(body, "UDP flood", "showing 0–10 of 25")

	// protection status change hits the (undocumented) prot/status endpoint
	flash("/server/"+testKVM+"/protstatus", "DDoS protection changed", url.Values{
		"ip": {"1.2.3.4"}, "status": {"permanent"},
	})

	// order catalog: kvm orderable, dedicated shown as sold out / external
	body = get("/order")
	want(body, "KVM S", `href="/order/bbbbbbbb-0000-0000-0000-000000000001"`)
	want(body, "DEDI L", "sold out")

	// order config page renders the OS list
	if body = get("/order/bbbbbbbb-0000-0000-0000-000000000001"); !strings.Contains(body, "Debian 12") {
		t.Fatal("order config missing OS list")
	}

	// placing the order forwards to the payment provider
	if loc := postLoc("/order/bbbbbbbb-0000-0000-0000-000000000001", url.Values{
		"os": {"cccccccc-0000-0000-0000-000000000001"}, "ipcount": {"1"},
		"paymentmethod": {"paypal"}, "credit": {"1"}, "tos": {"1"}, "privacy": {"1"},
	}); loc != "https://pay.example/checkout/555" {
		t.Fatalf("kvm order redirect: got %q", loc)
	}

	// access manager: code + both lists render, create/accept round-trip
	body = get("/access")
	if !strings.Contains(body, "ACCESS-CODE-99") {
		t.Fatal("access code not rendered")
	}
	want(body, "buddy", "team access")
	want(body, "Start server", `value="start" checked`)
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
	if body = get("/emaillog"); !strings.Contains(body, "Order #1234 confirmed") {
		t.Fatal("emaillog missing entries")
	}

	// non-KVM services are manageable: gameserver page shows SFTP/DB login data
	body = get("/server/aaaaaaaa-0000-0000-0000-000000000002")
	want(body, "gs1", "sftppw", "db.example")
	// generic key/value hardware view for non-KVM shapes
	body = get("/server/aaaaaaaa-0000-0000-0000-000000000002?tab=hardware")
	want(body, "Minecraft", "extra ram")

	// gameserver variables tab renders and saving a value round-trips
	body = get("/server/aaaaaaaa-0000-0000-0000-000000000002?tab=vars")
	want(body, "MAX_PLAYERS", `value="20"`)
	flash("/server/aaaaaaaa-0000-0000-0000-000000000002/var", "Variable saved", url.Values{"variable": {"MAX_PLAYERS"}, "value": {"32"}})

	// object storage: buckets and S3 keys tabs, bucket create round-trips
	body = get("/server/aaaaaaaa-0000-0000-0000-000000000007?tab=buckets")
	want(body, "backups.s3.fra.databucket.eu", "5.30 GB")
	// display flags gate the action sidebar per product: object storage has no
	// power buttons / reinstall / login data, gameservers have no noVNC or rescue
	if strings.Contains(body, `value="start"`) || strings.Contains(body, "reinstall") ||
		strings.Contains(body, "Login data") {
		t.Fatal("object storage page shows actions it should not have")
	}
	body = get("/server/aaaaaaaa-0000-0000-0000-000000000002")
	if strings.Contains(body, "noVNC") || strings.Contains(body, "rescue mode") {
		t.Fatal("gameserver page shows KVM-only actions")
	}
	want(body, `value="start"`, `value="restart"`)
	flash("/server/aaaaaaaa-0000-0000-0000-000000000007/bucket", "Bucket created", url.Values{"name": {"my-bucket"}})
	body = get("/server/aaaaaaaa-0000-0000-0000-000000000007?tab=keys")
	want(body, "AKtest123", `class="blur">SEKRIT456`)

	// IPv4 rDNS reset computes the default in-addr.arpa entry server-side
	flash("/server/"+testKVM+"/rdns", "rDNS updated", url.Values{"ip": {"1.2.3.4"}, "rdns": {""}, "reset": {"1"}})

	// files tab: listing, text-file view + save round-trip
	body = get("/server/aaaaaaaa-0000-0000-0000-000000000002?tab=files")
	want(body, "server.properties", "world.zip", "upload via the official panel")
	if body = get("/server/aaaaaaaa-0000-0000-0000-000000000002?tab=files&file=/server.properties"); !strings.Contains(body, "motd=hello") {
		t.Fatal("file content not shown")
	}
	flash("/server/aaaaaaaa-0000-0000-0000-000000000002/file/save", "File saved", url.Values{"path": {"/server.properties"}, "data": {"motd=changed"}})

	// mods: installed list, search, add round-trip
	if body = get("/server/aaaaaaaa-0000-0000-0000-000000000002?tab=mods"); !strings.Contains(body, "WorldEdit") {
		t.Fatal("installed mods not rendered")
	}
	if body = get("/server/aaaaaaaa-0000-0000-0000-000000000002?tab=mods&q=essentials"); !strings.Contains(body, "EssentialsX") {
		t.Fatal("mod search not rendered")
	}
	flash("/server/aaaaaaaa-0000-0000-0000-000000000002/mod/add", "Mod added", url.Values{"mod": {"essentialsx"}})

	// vars tab carries version + game changer for gameservers; console fallback modal present
	body = get("/server/aaaaaaaa-0000-0000-0000-000000000002?tab=vars")
	want(body, "change version", "change game", "1.21", "console-modal")
	flash("/server/aaaaaaaa-0000-0000-0000-000000000002/version", "Version change started", url.Values{"version": {"v2"}, "confirm": {"yes"}})
	flash("/server/aaaaaaaa-0000-0000-0000-000000000002/game", "Game change started", url.Values{"game": {"g-rust"}, "version": {"r1"}, "confirm": {"yes"}})

	// ports tab
	body = get("/server/aaaaaaaa-0000-0000-0000-000000000002?tab=ports")
	want(body, "25565", "add extra port")

	// addons tab + order checkout redirect; KVM upgrade checkout redirect
	body = get("/server/aaaaaaaa-0000-0000-0000-000000000002?tab=addons")
	want(body, "Traffic reset", "Extra RAM")
	if loc := postLoc("/server/aaaaaaaa-0000-0000-0000-000000000002/addon/order", url.Values{
		"addon": {"ram"}, "amount": {"2"}, "method": {"paypal"}, "credit": {"1"},
	}); loc != "https://pay.example/checkout/addon" {
		t.Fatalf("addon order redirect: got %q", loc)
	}
	if body = get("/server/" + testKVM + "?tab=billing"); !strings.Contains(body, "KVM M — 9.99") {
		t.Fatal("upgrade offer not rendered on billing tab")
	}
	if loc := postLoc("/server/"+testKVM+"/upgrade", url.Values{
		"package": {"up-m"}, "method": {"paypal"}, "credit": {"1"},
	}); loc != "https://pay.example/checkout/upg" {
		t.Fatalf("upgrade order redirect: got %q", loc)
	}

	// ticket thread renders, internal notes stay hidden, answering round-trips
	body = get("/tickets/4821")
	want(body, "It broke\nplease help", "We are on it")
	if strings.Contains(body, "secret note") {
		t.Fatal("internal ticket note must not be shown")
	}
	flash("/tickets/4821/answer", "Answer sent", url.Values{"text": {"thanks!"}})

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
