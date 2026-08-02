package main

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"maps"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

/* ── input validation (trust boundary: everything from the browser) ── */

// badInput reports an over-long or control-character-carrying form value.
func badInput(s string, max int) bool {
	return len(s) > max || strings.ContainsFunc(s, unicode.IsControl)
}

var (
	reAPIKey   = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
	reUUID     = regexp.MustCompile(`^[A-Fa-f0-9-]{8,64}$`)
	reHostname = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	reNotify   = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
	reTag      = regexp.MustCompile(`<[^>]*>`)
	// anything that has no business in a Content-Disposition filename
	reUnsafeName = regexp.MustCompile(`[^A-Za-z0-9_-]`)
)

// The API's activity feed embeds the official panel's HTML markup. Strip it to
// plain text — the template escapes output anyway, so leftovers can never
// render as markup; this is purely cosmetic.
func stripTags(s string) string {
	return html.UnescapeString(reTag.ReplaceAllString(s, ""))
}

// The API returns the literal string "null" for unnamed services.
func cleanName(s string) string {
	if s == "null" {
		return ""
	}
	return s
}

/* ── login ── */

func renderLogin(w http.ResponseWriter, r *http.Request, errMsg string, code int) {
	csrf := randHex()
	http.SetCookie(w, &http.Cookie{Name: "dplogin", Value: csrf, Path: "/login",
		MaxAge: 900, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: isHTTPS(r)})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	if err := loginTmpl.Execute(w, viewData{CSRF: csrf, Err: errMsg}); err != nil {
		log.Printf("template login: %v", err)
	}
}

func loginPage(w http.ResponseWriter, r *http.Request) {
	if getSession(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// a fixed code, not text: anything echoed here would appear in the panel's
	// own alert box directly above the API key field
	errMsg := ""
	if r.URL.Query().Get("err") == "rejected" {
		errMsg = "Your API key was rejected — please sign in again."
	}
	renderLogin(w, r, errMsg, http.StatusOK)
}

func loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !allowLogin(clientIP(r)) {
		renderLogin(w, r, "Too many attempts — wait a few minutes.", http.StatusTooManyRequests)
		return
	}
	c, err := r.Cookie("dplogin")
	if err != nil || len(c.Value) != 64 {
		renderLogin(w, r, "Form expired — please try again.", http.StatusForbidden)
		return
	}
	if !postGuard(w, r, c.Value) {
		return
	}

	key := strings.TrimSpace(r.PostFormValue("apikey"))
	if !reAPIKey.MatchString(key) {
		renderLogin(w, r, "That doesn't look like a Datalix API key.", http.StatusBadRequest)
		return
	}
	uid := strings.TrimSpace(r.PostFormValue("userid"))
	if uid != "" && !reUUID.MatchString(uid) {
		renderLogin(w, r, "That doesn't look like a valid user ID.", http.StatusBadRequest)
		return
	}

	api := API{token: key}
	username := ""
	var ki struct {
		UserInfo map[string]any `json:"userInfo"`
	}
	if err := api.get("/user/apikey/"+url.PathEscape(key), &ki); err == nil {
		if v, ok := ki.UserInfo["username"].(string); ok {
			username = v
		}
		if uid == "" {
			for _, k := range []string{"id", "userid", "userId", "user"} {
				if v, ok := ki.UserInfo[k].(string); ok && reUUID.MatchString(v) {
					uid = v
					break
				}
			}
		}
	}
	if uid == "" {
		// Token might still be fine — tell the user what's actually wrong.
		var svcs []Service
		if err := api.get("/service/list", &svcs); err != nil {
			renderLogin(w, r, "API key rejected: "+err.Error(), http.StatusUnauthorized)
			return
		}
		renderLogin(w, r, "Key is valid, but your user ID couldn't be auto-detected. Paste it into the User ID field (official panel → Account).", http.StatusOK)
		return
	}

	var dash Dashboard
	if err := api.get("/user/"+url.PathEscape(uid)+"/dashboard", &dash); err != nil {
		renderLogin(w, r, "Sign-in failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	id := newSession(key, uid, username)
	setSessionCookie(w, r, id)
	http.SetCookie(w, &http.Cookie{Name: "dplogin", Value: "", Path: "/login", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

/* ── pages ── */

// vd builds the common view data every authenticated page shares.
func vd(title, page string, s *session, r *http.Request) viewData {
	v := viewData{Title: title, Page: page, CSRF: s.csrf, User: s.username}
	v.Msg, v.Err = takeFlash(r)
	return v
}

func greeting() string {
	switch h := time.Now().Hour(); {
	case h < 5:
		return "Good night"
	case h < 12:
		return "Good morning"
	case h < 18:
		return "Good afternoon"
	default:
		return "Good evening"
	}
}

type overviewView struct {
	Dashboard  *Dashboard
	Greeting   string
	EmailState int // 0=unverified, 1=verified, 2=throwaway
	Servers    []Service
}

func overviewPage(w http.ResponseWriter, r *http.Request, s *session) {
	api := API{token: s.token}
	v := vd("Dashboard", "overview", s, r)

	var all []Service
	if err := api.get("/service/list", &all); err != nil {
		if isAuthError(err) {
			apiFail(w, r, "/", err)
			return
		}
		v.Err = cmp.Or(v.Err, err.Error())
	}
	ov := overviewView{Greeting: greeting()}
	for i := range all {
		all[i].Name = cleanName(all[i].Name)
	}
	ov.Servers = all
	var dash Dashboard
	if err := api.get("/user/"+url.PathEscape(s.userID)+"/dashboard", &dash); err == nil {
		for i := range dash.Activity {
			dash.Activity[i].Text = stripTags(dash.Activity[i].Text)
		}
		ov.Dashboard = &dash
		ov.EmailState = int(dash.EmailVerified)
	}
	v.Data = ov
	render(w, "overview", v)
}

type servicesView struct {
	Services []Service
	Deleted  bool
	Query    string
}

func servicesPage(w http.ResponseWriter, r *http.Request, s *session) {
	deleted := r.URL.Query().Get("tab") == "deleted"
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if badInput(q, 64) {
		q = ""
	}
	typ := "active"
	if deleted {
		typ = "inactive"
	}
	path := "/service/list?type=" + typ
	if q != "" {
		path += "&search=" + url.QueryEscape(q)
	}

	v := vd("Services", "services", s, r)
	var list []Service
	if err := (API{token: s.token}).get(path, &list); err != nil {
		if isAuthError(err) {
			apiFail(w, r, "/services", err)
			return
		}
		v.Err = cmp.Or(v.Err, err.Error())
	}
	for i := range list {
		list[i].Name = cleanName(list[i].Name)
	}
	sort.SliceStable(list, func(i, j int) bool { return bool(list[i].Fav) && !bool(list[j].Fav) })
	v.Data = servicesView{Services: list, Deleted: deleted, Query: q}
	render(w, "services", v)
}

func servicesFav(w http.ResponseWriter, r *http.Request, s *session) {
	id := r.PathValue("id")
	if !reUUID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	api := API{token: s.token}
	var err error
	if r.PostFormValue("on") == "1" {
		err = api.post("/service/"+url.PathEscape(id)+"/fav", nil)
	} else {
		err = api.delete("/service/" + url.PathEscape(id) + "/fav")
	}
	if err != nil {
		apiFail(w, r, "/services", err)
		return
	}
	flashOK(w, r, "/services", "Favorites updated.")
}

func servicesHide(w http.ResponseWriter, r *http.Request, s *session) {
	id := r.PathValue("id")
	if !reUUID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	if err := (API{token: s.token}).post("/service/"+url.PathEscape(id)+"/hide", nil); err != nil {
		apiFail(w, r, "/services?tab=deleted", err)
		return
	}
	flashOK(w, r, "/services?tab=deleted", "Service hidden.")
}

type serverView struct {
	ID          string
	Tab         string
	Info        ServiceInfo
	Hardware    *Hardware
	IPs         *ServiceIPs
	Traffic     *TrafficHistory
	Backups     []Backup
	OSList      []OSEntry
	Logs        []ActionLog
	Cron        []CronJob
	Incidents   *IncidentsPage
	Search      string
	CustomISOs  []CustomISO
	ISOList     []OSEntry
	UplinkMB    int // product uplink converted to MB/s for the edit form
	MaxUplinkMB int
	SSHKeys     []SSHKey
	// addons + upgrade
	Addons      []ServiceAddon
	AddonOffers []AddonOffer
	PayMethods  []payMethod
	Upgrades    []upgradeRow
	// ddos log pagination
	IncFrom, IncTo, IncPrev, IncNext int
	IncHasPrev, IncHasNext           bool
}

type upgradeRow struct{ ID, Label, Details string }

// upgradeRowOf renders one GET /upgrade entry; field sets differ per product,
// so everything beyond the common fields is flattened generically.
func upgradeRowOf(m map[string]any) upgradeRow {
	str := func(k string) string {
		switch v := m[k].(type) {
		case string:
			return v
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		}
		return ""
	}
	num := func(k string) float64 { v, _ := m[k].(float64); return v }
	row := upgradeRow{ID: str("id")}
	row.Label = fmt.Sprintf("%s — %.2f €/mo (pay now %.2f €)",
		strings.TrimSpace(str("displayname")), num("monthlyprice"), num("onetimepayment"))
	for _, k := range []string{"id", "displayname", "monthlyprice", "onetimepayment", "active", "line"} {
		delete(m, k)
	}
	row.Details = strings.Join(kvParts(m), " · ")
	return row
}

// kvParts flattens an unknown-shape API object (scalars plus one level of
// object arrays, like the per-product fields of an upgrade offer) for display.
func kvParts(raw map[string]any) []string {
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(raw)) {
		switch v := raw[k].(type) {
		case string, float64, bool:
			parts = append(parts, fmt.Sprintf("%s %v", k, v))
		case []any:
			var lines []string
			for _, it := range v {
				if m, ok := it.(map[string]any); ok {
					lines = append(lines, strings.Join(kvParts(m), ", "))
				} else {
					lines = append(lines, fmt.Sprint(it))
				}
			}
			if len(lines) > 0 {
				parts = append(parts, k+" "+strings.Join(lines, " · "))
			}
		}
	}
	return parts
}

var serverTabs = map[string]bool{"network": true, "hardware": true, "live": true,
	"traffic": true, "backups": true, "tasks": true, "ddos": true,
	"logs": true, "settings": true, "billing": true, "danger": true,
	"sshkeys": true, "addons": true}

func serverPage(w http.ResponseWriter, r *http.Request, s *session) {
	id := r.PathValue("id")
	if !reUUID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	tab := r.URL.Query().Get("tab")
	if !serverTabs[tab] {
		tab = "network"
	}
	api := API{token: s.token}
	pid := url.PathEscape(id)
	var info ServiceInfo
	if err := api.get("/service/"+pid, &info); err != nil {
		apiFail(w, r, "/services", err)
		return
	}
	info.Service.Name = cleanName(info.Service.Name)
	// Nothix manages KVM servers only — everything else lives in the official panel
	if info.Service.ProductID != 2 {
		apiFail(w, r, "/services",
			errors.New("This service type is managed in the official Datalix panel (datalix.eu)."))
		return
	}

	// tabs fetch only what they show — keeps us far away from the API rate limits
	sv := serverView{ID: id, Tab: tab, Info: info}
	switch tab {
	case "network":
		if info.Display.IP {
			var ips ServiceIPs
			if api.get("/service/"+pid+"/ip", &ips) == nil {
				sv.IPs = &ips
			}
		}
	case "hardware":
		if info.Display.Hardware {
			var hw Hardware
			if api.get("/service/"+pid+"/hardware", &hw) == nil {
				sv.Hardware = &hw
			}
		}
	case "traffic":
		if info.Display.Traffic {
			var tr TrafficHistory
			if api.get("/service/"+pid+"/traffic", &tr) == nil {
				if tr.Max > 0 { // compute % ourselves; the API's example data is ambiguous
					tr.NormalPercentage = float64(tr.Current) / float64(tr.Max) * 100
				}
				scaleTrafficBars(tr.History.Last30Days)
				scaleTrafficBars(tr.History.Months)
				sv.Traffic = &tr
			}
		}
	case "backups":
		if info.Display.Backup {
			api.get("/service/"+pid+"/backup", &sv.Backups)
		}
	case "sshkeys":
		if info.Display.SSHKeys {
			api.get("/service/"+pid+"/sshkeys", &sv.SSHKeys)
		}
	case "addons":
		if info.Service.Addons {
			api.get("/service/"+pid+"/addons", &sv.Addons)
			api.get("/service/"+pid+"/addons/list", &sv.AddonOffers)
			sv.PayMethods = payMethods
		}
	case "billing":
		var raws []map[string]any
		if api.get("/service/"+pid+"/upgrade", &raws) == nil {
			for _, m := range raws {
				sv.Upgrades = append(sv.Upgrades, upgradeRowOf(m))
			}
		}
		sv.PayMethods = payMethods
	case "tasks":
		api.get("/service/"+pid+"/cron", &sv.Cron)
	case "ddos":
		start, _ := strconv.Atoi(r.URL.Query().Get("start"))
		start = max(start, 0)
		sv.Search = strings.TrimSpace(r.URL.Query().Get("q"))
		if len(sv.Search) > 64 {
			sv.Search = sv.Search[:64]
		}
		var inc IncidentsPage
		if api.get("/service/"+pid+"/incidents?start="+strconv.Itoa(start)+"&search="+url.QueryEscape(sv.Search), &inc) == nil {
			sv.Incidents = &inc
			step := max(inc.PageInfo.StepSize, 10)
			sv.IncFrom = inc.PageInfo.Last
			sv.IncTo = min(sv.IncFrom+step, inc.PageInfo.Total)
			sv.IncHasPrev = start > 0
			sv.IncPrev = max(sv.IncFrom-step, 0)
			sv.IncNext = sv.IncFrom + step
			sv.IncHasNext = sv.IncTo < inc.PageInfo.Total
		}
	case "settings":
		if info.Display.CustomISO {
			api.get("/service/"+pid+"/iso/custom/list", &sv.CustomISOs)
		}
		if info.Display.ISOMount {
			// undocumented list endpoint — degrade to an empty select if missing
			api.get("/service/"+pid+"/iso", &sv.ISOList)
		}
	case "logs":
		api.get("/service/"+pid+"/actionlogs", &sv.Logs)
	case "danger":
		api.get("/service/"+pid+"/os", &sv.OSList)
	}
	sv.UplinkMB = int(info.Product.Uplink) / 10
	sv.MaxUplinkMB = int(info.Product.MaxUplink) / 10

	v := vd("Server", "services", s, r)
	v.Data = sv
	render(w, "server", v)
}

// order status codes per the official panel's JS
func orderStatus(s int) (string, string) {
	switch s {
	case 0:
		return "Unpaid", "err"
	case 1, 2:
		return "Completed", "ok"
	case 3:
		return "Canceled", "warn"
	case 10:
		return "Waiting for manual review", "warn"
	}
	return "Error", "err"
}

var orderTypes = map[string]string{
	"kvmServerPacket": "KVM package", "saleServer": "Dedicated clearance", "saleNewServer": "Dedicated clearance",
	"packetServer": "Dedicated package", "webspacePacket": "Webspace package", "orderGameserver": "Gameserver",
	"invoice": "Invoice", "payByInvoice": "Invoice", "serviceAddon": "Addon", "serviceAutoRenew": "Auto-renew",
	"renewServer": "Service extend", "serviceUpgrade": "Service upgrade", "topupcredit": "Top up credit",
	"serviceMassRenew": "Mass renew", "nextcloudPacket": "Nextcloud package", "objectStorage": "Object storage",
	"serviceAutoRenewInit": "Auto-renew init",
}

var brToSep = strings.NewReplacer("<br>", " · ", "<br/>", " · ", "<br />", " · ")

type orderRow struct {
	Order
	StatusText, StatusClass, TypeText string
}

type ordersView struct {
	Rows                 []orderRow
	From, To, Total      int
	PrevStart, NextStart int
	HasPrev, HasNext     bool
}

func ordersPage(w http.ResponseWriter, r *http.Request, s *session) {
	start, _ := strconv.Atoi(r.URL.Query().Get("start"))
	if start < 0 || start > 1_000_000 {
		start = 0
	}
	v := vd("Orders", "orders", s, r)
	var op OrdersPage
	if err := (API{token: s.token}).get("/user/"+url.PathEscape(s.userID)+"/orders?start="+strconv.Itoa(start), &op); err != nil {
		if isAuthError(err) {
			apiFail(w, r, "/orders", err)
			return
		}
		v.Err = cmp.Or(v.Err, err.Error())
	}
	ov := ordersView{Total: op.PageInfo.Total}
	for _, o := range op.Data {
		o.OrderInfo = stripTags(brToSep.Replace(o.OrderInfo))
		st, cls := orderStatus(int(o.Status))
		ov.Rows = append(ov.Rows, orderRow{Order: o, StatusText: st, StatusClass: cls,
			TypeText: cmp.Or(orderTypes[o.Type], o.Type)})
	}
	step := cmp.Or(op.PageInfo.StepSize, 10)
	ov.From = op.PageInfo.Last
	ov.To = min(ov.From+step, ov.Total)
	ov.HasPrev = start > 0
	ov.PrevStart = max(ov.From-step, 0)
	ov.NextStart = ov.From + step
	ov.HasNext = ov.To < ov.Total
	v.Data = ov
	render(w, "orders", v)
}

func accountPage(w http.ResponseWriter, r *http.Request, s *session) {
	var invoices []Invoice
	if err := (API{token: s.token}).get("/user/"+url.PathEscape(s.userID)+"/invoice/list", &invoices); isAuthError(err) {
		apiFail(w, r, "/account", err)
		return
	}
	v := vd("Invoices", "account", s, r)
	v.Data = struct{ Invoices []Invoice }{invoices}
	render(w, "account", v)
}

// invoiceView proxies the invoice PDF through the panel so the API token
// never reaches the browser. The spec leaves the response shape of
// GET /user/{id}/invoice/{id} undocumented (Sevdesk pass-through), so accept
// both a raw PDF body and a JSON envelope carrying it as base64.
func invoiceView(w http.ResponseWriter, r *http.Request, s *session) {
	id := r.PathValue("id")
	data, err := (API{token: s.token}).raw(http.MethodGet,
		"/user/"+url.PathEscape(s.userID)+"/invoice/"+url.PathEscape(id), nil)
	if err != nil {
		apiFail(w, r, "/account", err)
		return
	}
	if !bytes.HasPrefix(data, []byte("%PDF")) {
		var v any
		json.Unmarshal(data, &v)
		if data = findPDF(v); data == nil {
			apiFail(w, r, "/account", errors.New("invoice download unavailable"))
			return
		}
	}
	name := reUnsafeName.ReplaceAllString(id, "")
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `inline; filename="invoice-`+name+`.pdf"`)
	w.Write(data)
}

// findPDF walks arbitrary decoded JSON for a base64 string that is a PDF.
func findPDF(v any) []byte {
	switch t := v.(type) {
	case string:
		clean := strings.NewReplacer("\n", "", "\r", "").Replace(t)
		if dec, err := base64.StdEncoding.DecodeString(clean); err == nil && bytes.HasPrefix(dec, []byte("%PDF")) {
			return dec
		}
	case map[string]any:
		for _, c := range t {
			if p := findPDF(c); p != nil {
				return p
			}
		}
	case []any:
		for _, c := range t {
			if p := findPDF(c); p != nil {
				return p
			}
		}
	}
	return nil
}

func transactionsPage(w http.ResponseWriter, r *http.Request, s *session) {
	var entries []CreditLogEntry
	if err := (API{token: s.token}).get("/user/"+url.PathEscape(s.userID)+"/credit/log", &entries); isAuthError(err) {
		apiFail(w, r, "/transactions", err)
		return
	}
	v := vd("Transactions", "transactions", s, r)
	v.Data = struct{ CreditLog []CreditLogEntry }{CreditLog: entries}
	render(w, "transactions", v)
}

type donationsView struct {
	Info      DonationInfo
	Links     []DonationLink
	Donations []Donation
}

func donationsPage(w http.ResponseWriter, r *http.Request, s *session) {
	api := API{token: s.token}
	u := "/user/" + url.PathEscape(s.userID)

	dv := donationsView{}
	if err := api.get(u+"/credit/donation/info", &dv.Info); isAuthError(err) {
		apiFail(w, r, "/donations", err)
		return
	}
	api.get(u+"/credit/donation/link/list", &dv.Links)
	api.get(u+"/credit/donation/list", &dv.Donations)

	v := vd("Donation links", "donations", s, r)
	v.Data = dv
	render(w, "donations", v)
}

func donationLinkCreate(w http.ResponseWriter, r *http.Request, s *session) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" || len(name) > 64 {
		http.Error(w, "invalid link name", http.StatusBadRequest)
		return
	}
	userAction(w, r, s, "/donations", "Donation link created.", func(api API, uid string) error {
		return api.post("/user/"+uid+"/credit/donation/link", map[string]string{"link": name})
	})
}

type affiliateView struct {
	Info  AffiliateInfo
	Links []AffiliateLink
	Log   []AffiliateTransaction
}

func affiliatePage(w http.ResponseWriter, r *http.Request, s *session) {
	api := API{token: s.token}
	u := "/user/" + url.PathEscape(s.userID)

	av := affiliateView{}
	if err := api.get(u+"/affiliate/info", &av.Info); isAuthError(err) {
		apiFail(w, r, "/affiliate", err)
		return
	}
	api.get(u+"/affiliate", &av.Links)
	api.get(u+"/affiliate/list", &av.Log)

	v := vd("Affiliate links", "affiliate", s, r)
	v.Data = av
	render(w, "affiliate", v)
}

func affiliateLinkCreate(w http.ResponseWriter, r *http.Request, s *session) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" || len(name) > 64 {
		http.Error(w, "invalid link name", http.StatusBadRequest)
		return
	}
	userAction(w, r, s, "/affiliate", "Affiliate link created.", func(api API, uid string) error {
		return api.post("/user/"+uid+"/affiliate", map[string]string{"name": name})
	})
}

/* ── top up credit ── */

type payMethod struct {
	ID, Name, Logo string
}

// Crypto is read from templates ({{if .Crypto}}); methods render like fields.
func (p payMethod) Crypto() bool { return strings.HasPrefix(p.ID, "cryptocurrency") }

// payMethods mirrors the official panel's hardcoded payment method list;
// logos are vendored copies of cdn.datalix.de/images/payment/* (CSP: img-src 'self').
var payMethods = []payMethod{
	{"paypal", "PayPal", "paypal.png"}, {"creditcard", "CreditCard", "cc.png"},
	{"psc", "PaySafeCard", "paysafecard.svg"}, {"eps", "EPS", "eps.png"},
	{"przelewy24", "Przelewy24", "przelewy24.svg"}, {"cryptocurrency-btc", "BTC", "bitcoin.webp"},
	{"cryptocurrency-ltc", "Litecoin", "ltc.png"}, {"alipay", "Alipay", "alipay.png"},
	{"cryptocurrency-xmr", "Monero", "monero.png"}, {"banktransfer", "Bank transfer", "sepa.png"},
	{"ideal", "iDEAL", "ideal.svg"}, {"cryptocurrency-eth", "ETH", "ethereum.svg"},
	{"cryptocurrency-bch", "BCH", "bitcoin-cash-bch-logo.svg"},
	{"cryptocurrency-usdt.trc20", "USDT.TRC20", "tether-usdt-logo.png"},
	{"cryptocurrency-usdt.prc20", "USDT.PRC20", "tether-usdt-logo.png"},
	{"cryptocurrency-usdt.bep20", "USDT.BEP20", "tether-usdt-logo.png"},
	{"cryptocurrency-btc.ln", "BTC.LN", "btc-ln-logo.png"},
	{"cryptocurrency-USDC", "USDC", "usdc.webp"},
	{"cryptocurrency-USDC.BEP20", "USDC.BEP20", "usdc.webp"},
	{"cryptocurrency-USDC.PRC20", "USDC.PRC20", "usdc.webp"},
	{"cryptocurrency-USDC.SOL", "USDC.SOL", "usdc.webp"},
	{"cryptocurrency-SOL", "SOL", "solana-sol-logo.png"},
	{"cryptocurrency-TRX", "TRX", "TRX.png"},
}

func payMethodByID(id string) *payMethod {
	if i := slices.IndexFunc(payMethods, func(p payMethod) bool { return p.ID == id }); i >= 0 {
		return &payMethods[i]
	}
	return nil
}

type creditView struct {
	Methods     []payMethod
	Countries   []UserCountry
	InvoiceData *InvoiceData
	Open        string // payment method to re-open the modal for (after an invoice data save)
}

func creditPage(w http.ResponseWriter, r *http.Request, s *session) {
	api := API{token: s.token}
	u := "/user/" + url.PathEscape(s.userID)

	cv := creditView{Methods: payMethods}
	if err := api.get(u+"/countrys", &cv.Countries); isAuthError(err) {
		apiFail(w, r, "/credit", err)
		return
	}
	var inv InvoiceData
	if api.get(u+"/invoicedata", &inv) == nil {
		cv.InvoiceData = &inv
	}
	if m := payMethodByID(r.URL.Query().Get("open")); m != nil {
		cv.Open = m.ID
	}
	v := vd("Top up credit", "credit", s, r)
	v.Data = cv
	render(w, "credit", v)
}

// creditTopup creates the credit order and forwards the browser to the payment
// provider: POST credit/add → {id}, POST order/{id}/pay → provider URL.
func creditTopup(w http.ResponseWriter, r *http.Request, s *session) {
	amount := strings.TrimSpace(r.PostFormValue("amount"))
	if a, err := strconv.ParseFloat(amount, 64); err != nil || a < 1 || a > 100000 {
		http.Error(w, "invalid amount", http.StatusBadRequest)
		return
	}
	method := payMethodByID(r.PostFormValue("method"))
	if method == nil {
		http.Error(w, "invalid payment method", http.StatusBadRequest)
		return
	}
	if r.PostFormValue("tos") != "1" || r.PostFormValue("privacy") != "1" || r.PostFormValue("norefund") != "1" {
		apiFail(w, r, "/credit", errors.New("Please accept the terms, the privacy policy and the credit conditions."))
		return
	}

	api := API{token: s.token}
	u := "/user/" + url.PathEscape(s.userID)

	// tax country comes from the saved invoice data, like the official panel
	var inv InvoiceData
	api.get(u+"/invoicedata", &inv)
	if inv.FirstName == "" || inv.LastName == "" || inv.Street == "" || inv.Zip == "" || inv.City == "" {
		apiFail(w, r, "/credit", errors.New("Please fill in and save your invoice data first."))
		return
	}

	createAndPay(w, r, api, u+"/credit/add",
		map[string]string{"amount": amount, "tax": string(inv.Country)}, method.ID, "/credit")
}

// createAndPay creates an order at path, pays it, and forwards the browser to
// the payment provider's checkout link.
func createAndPay(w http.ResponseWriter, r *http.Request, api API, path string,
	form map[string]string, method, target string) {
	var created struct {
		ID Str `json:"id"`
	}
	if err := api.postOut(path, form, &created); err != nil {
		apiFail(w, r, target, err)
		return
	}
	if created.ID == "" {
		apiFail(w, r, target, errors.New("order could not be created"))
		return
	}
	var pay struct {
		URL  string `json:"url"`
		Link string `json:"link"`
	}
	if err := api.postOut("/order/"+url.PathEscape(string(created.ID))+"/pay",
		map[string]string{"paymentMethod": method}, &pay); err != nil {
		apiFail(w, r, target, err)
		return
	}
	dest := cmp.Or(pay.URL, pay.Link)
	if !strings.HasPrefix(dest, "https://") {
		apiFail(w, r, target, errors.New("payment provider returned no checkout link"))
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// creditInvoiceData saves invoice data from the top-up modal and re-opens it.
func creditInvoiceData(w http.ResponseWriter, r *http.Request, s *session) {
	target := "/credit"
	if m := payMethodByID(r.PostFormValue("method")); m != nil {
		target = "/credit?open=" + url.QueryEscape(m.ID)
	}
	invoiceDataSubmit(w, r, s, target)
}

/* ── purchase by invoice ── */

// fallback when GET /payment/paymentmethods (undocumented) is unavailable —
// the static list from the official page's markup
var pbiFallbackMethods = []PaymentMethodOption{
	{Method: "paypal", Display: "PayPal"}, {Method: "sofort", Display: "Sofort"},
	{Method: "psc", Display: "PaySafeCard"}, {Method: "creditcard", Display: "CreditCard (Mastercard, American Express, Visa, ApplePay)"},
}

var reToken = regexp.MustCompile(`^[A-Za-z0-9.-]{1,64}$`)

// validPbiID accepts an invoice UUID or the API's synthetic "default" entry.
func validPbiID(id string) bool { return id == "default" || reUUID.MatchString(id) }

type pbiView struct {
	Info       PayByInvoiceInfo
	Unpaid     []UnpaidEntry
	Invoices   []OwnInvoice
	PayOptions []PaymentMethodOption
}

func paybyinvoicePage(w http.ResponseWriter, r *http.Request, s *session) {
	api := API{token: s.token}
	u := "/user/" + url.PathEscape(s.userID)

	pv := pbiView{}
	if err := api.get(u+"/credit/paybyinvoice/info", &pv.Info); isAuthError(err) {
		apiFail(w, r, "/paybyinvoice", err)
		return
	}
	api.get(u+"/credit/log/unpaid", &pv.Unpaid)
	api.get(u+"/credit/paybyinvoice/list", &pv.Invoices)
	if api.get("/payment/paymentmethods", &pv.PayOptions) != nil || len(pv.PayOptions) == 0 {
		pv.PayOptions = pbiFallbackMethods
	}

	v := vd("Purchase by invoice", "paybyinvoice", s, r)
	v.Data = pv
	render(w, "paybyinvoice", v)
}

func pbiCreate(w http.ResponseWriter, r *http.Request, s *session) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" || len(name) > 64 {
		http.Error(w, "invalid invoice name", http.StatusBadRequest)
		return
	}
	userAction(w, r, s, "/paybyinvoice", "Own invoice created.", func(api API, uid string) error {
		return api.post("/user/"+uid+"/credit/paybyinvoice", map[string]string{"name": name})
	})
}

func pbiRename(w http.ResponseWriter, r *http.Request, s *session) {
	id := r.PostFormValue("id")
	name := strings.TrimSpace(r.PostFormValue("name"))
	if !reUUID.MatchString(id) || name == "" || len(name) > 64 {
		http.Error(w, "invalid invoice data", http.StatusBadRequest)
		return
	}
	userAction(w, r, s, "/paybyinvoice", "Own invoice renamed.", func(api API, uid string) error {
		return api.post("/user/"+uid+"/credit/paybyinvoice/"+id, map[string]string{"name": name})
	})
}

func pbiReassign(w http.ResponseWriter, r *http.Request, s *session) {
	invoice := r.PostFormValue("invoice")
	transaction := r.PostFormValue("transaction")
	if !validPbiID(invoice) || !reToken.MatchString(transaction) {
		http.Error(w, "invalid reassignment", http.StatusBadRequest)
		return
	}
	userAction(w, r, s, "/paybyinvoice", "Transaction reassigned.", func(api API, uid string) error {
		return api.post("/user/"+uid+"/credit/paybyinvoice/transaction",
			map[string]string{"invoice": invoice, "transaction": transaction})
	})
}

func pbiPay(w http.ResponseWriter, r *http.Request, s *session) {
	id := r.PostFormValue("id")
	method := r.PostFormValue("paymentmethod")
	if !validPbiID(id) || !reToken.MatchString(method) {
		http.Error(w, "invalid payment", http.StatusBadRequest)
		return
	}
	api := API{token: s.token}
	payPath := "/user/" + url.PathEscape(s.userID) + "/credit/paybyinvoice/" + id + "/pay"
	form := map[string]string{"paymentmethod": method}
	// paying with credit settles immediately and returns no order to forward to
	if method == "credit" {
		if err := api.post(payPath, form); err != nil {
			apiFail(w, r, "/paybyinvoice", err)
			return
		}
		flashOK(w, r, "/paybyinvoice", "Invoice paid with credit.")
		return
	}
	createAndPay(w, r, api, payPath, form, method, "/paybyinvoice")
}

/* ── order ── */

func orderPage(w http.ResponseWriter, r *http.Request, s *session) {
	var packets []CatalogPacket
	if err := (API{token: s.token}).get("/reseller/packet/list", &packets); isAuthError(err) {
		apiFail(w, r, "/order", err)
		return
	}
	v := vd("Order", "order", s, r)
	v.Data = struct{ Packets []CatalogPacket }{Packets: packets}
	render(w, "order", v)
}

type orderConfigView struct {
	Packet     KVMPacket
	OSList     []OSEntry
	PayOptions []PaymentMethodOption
}

func orderConfigPage(w http.ResponseWriter, r *http.Request, s *session) {
	pkt := r.PathValue("packet")
	if !reUUID.MatchString(pkt) {
		http.NotFound(w, r)
		return
	}
	api := API{token: s.token}
	ov := orderConfigView{}
	if err := api.get("/kvmserver/packet/"+pkt, &ov.Packet); err != nil {
		apiFail(w, r, "/order", err)
		return
	}
	api.get("/kvmserver/packet/"+pkt+"/os", &ov.OSList)
	if api.get("/payment/paymentmethods", &ov.PayOptions) != nil || len(ov.PayOptions) == 0 {
		ov.PayOptions = pbiFallbackMethods
	}
	v := vd("Order", "order", s, r)
	v.Data = ov
	render(w, "order_config", v)
}

func orderSubmit(w http.ResponseWriter, r *http.Request, s *session) {
	pkt := r.PathValue("packet")
	osID := r.PostFormValue("os")
	method := r.PostFormValue("paymentmethod")
	ipcount := r.PostFormValue("ipcount")
	if !reUUID.MatchString(pkt) || !reUUID.MatchString(osID) || !reToken.MatchString(method) {
		http.Error(w, "invalid order", http.StatusBadRequest)
		return
	}
	if n, err := strconv.Atoi(ipcount); err != nil || n < 0 || n > 64 {
		http.Error(w, "invalid ip count", http.StatusBadRequest)
		return
	}
	target := "/order/" + pkt
	if r.PostFormValue("tos") != "1" || r.PostFormValue("privacy") != "1" {
		apiFail(w, r, target, errors.New("Please accept the terms and the privacy policy."))
		return
	}

	api := API{token: s.token}
	var created struct {
		ID Str `json:"id"`
	}
	if err := api.postOut("/order/kvmserver/"+pkt, map[string]string{
		"paymentMethod": method, "os": osID, "ipcount": ipcount, "credit": chk(r, "credit"),
	}, &created); err != nil {
		apiFail(w, r, target, err)
		return
	}
	if created.ID == "" {
		apiFail(w, r, target, errors.New("order could not be created"))
		return
	}
	// pay the order; when credit covers it fully there is no checkout link
	var pay struct {
		URL  string `json:"url"`
		Link string `json:"link"`
	}
	err := api.postOut("/order/"+url.PathEscape(string(created.ID))+"/pay",
		map[string]string{"paymentMethod": method}, &pay)
	dest := cmp.Or(pay.URL, pay.Link)
	if err == nil && strings.HasPrefix(dest, "https://") {
		http.Redirect(w, r, dest, http.StatusSeeOther)
		return
	}
	flashOK(w, r, "/orders", "Order placed — check its status below.")
}

type ticketsView struct {
	Tickets     []Ticket
	Closed      bool
	Unavailable bool
}

func ticketsPage(w http.ResponseWriter, r *http.Request, s *session) {
	closed := r.URL.Query().Get("tab") == "closed"
	status := "allopen"
	if closed {
		status = "closed"
	}
	v := vd("Tickets", "tickets", s, r)
	tv := ticketsView{Closed: closed}
	// undocumented endpoint (used by the official panel) — degrade gracefully
	if err := (API{token: s.token}).get("/support/ticket/list?status="+status, &tv.Tickets); err != nil {
		if isAuthError(err) {
			apiFail(w, r, "/tickets", err)
			return
		}
		tv.Unavailable = true
	}
	v.Data = tv
	render(w, "tickets", v)
}

var reTicketID = regexp.MustCompile(`^[0-9]{1,20}$`)

type ticketMsg struct {
	Author string
	Time   int64
	Admin  bool
	Text   string
}

func ticketViewPage(w http.ResponseWriter, r *http.Request, s *session) {
	id := r.PathValue("id")
	if !reTicketID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	var td TicketDetail
	// undocumented endpoint mirroring the reseller ticket details
	if err := (API{token: s.token}).get("/support/ticket/"+url.PathEscape(id), &td); err != nil {
		apiFail(w, r, "/tickets", err)
		return
	}
	msgs := make([]ticketMsg, 0, len(td.Answers))
	for _, a := range td.Answers {
		if a.Internal {
			continue
		}
		msgs = append(msgs, ticketMsg{
			Author: a.Author.Username,
			Time:   a.CreatedOn,
			Admin:  bool(a.Admin),
			Text:   stripTags(strings.ReplaceAll(a.Content, "<br>", "\n")),
		})
	}
	v := vd(fmt.Sprintf("Ticket #%s", id), "tickets", s, r)
	v.Data = struct {
		ID     string
		Ticket TicketDetail
		Msgs   []ticketMsg
	}{id, td, msgs}
	render(w, "ticket_view", v)
}

func ticketAnswer(w http.ResponseWriter, r *http.Request, s *session) {
	id := r.PathValue("id")
	text := strings.TrimSpace(r.PostFormValue("text"))
	if !reTicketID.MatchString(id) || text == "" || len(text) > 10000 {
		http.Error(w, "invalid answer", http.StatusBadRequest)
		return
	}
	if err := (API{token: s.token}).post("/support/ticket/"+url.PathEscape(id)+"/answer",
		map[string]string{"text": text}); err != nil {
		apiFail(w, r, "/tickets/"+id, err)
		return
	}
	flashOK(w, r, "/tickets/"+id, "Answer sent.")
}

func ticketNewPage(w http.ResponseWriter, r *http.Request, s *session) {
	v := vd("Create Ticket", "createticket", s, r)
	var services []Service
	(API{token: s.token}).get("/service/list?type=active", &services)
	for i := range services {
		services[i].Name = cleanName(services[i].Name)
	}
	v.Data = struct{ Services []Service }{Services: services}
	render(w, "ticket_new", v)
}

func ticketCreate(w http.ResponseWriter, r *http.Request, s *session) {
	title := strings.TrimSpace(r.PostFormValue("title"))
	text := strings.TrimSpace(r.PostFormValue("text"))
	service := r.PostFormValue("service")
	if title == "" || badInput(title, 128) ||
		text == "" || len(text) > 10000 {
		http.Error(w, "invalid ticket data", http.StatusBadRequest)
		return
	}
	if service != "" && service != "none" && !reUUID.MatchString(service) {
		http.Error(w, "invalid service", http.StatusBadRequest)
		return
	}
	service = cmp.Or(service, "none")
	var created struct {
		ID Num `json:"id"`
	}
	if err := (API{token: s.token}).postOut("/support/ticket",
		map[string]string{"title": title, "text": text, "service": service}, &created); err != nil {
		apiFail(w, r, "/tickets/new", err)
		return
	}
	msg := "Ticket created — support will get back to you."
	if created.ID > 0 {
		msg = fmt.Sprintf("Ticket #%.0f created — support will get back to you.", float64(created.ID))
	}
	flashOK(w, r, "/tickets", msg)
}

func supportPage(w http.ResponseWriter, r *http.Request, s *session) {
	api := API{token: s.token}
	var dash Dashboard
	if err := api.get("/user/"+url.PathEscape(s.userID)+"/dashboard", &dash); isAuthError(err) {
		apiFail(w, r, "/support", err)
		return
	}
	v := vd("Support", "support", s, r)
	v.Data = struct{ Pin string }{Pin: dash.SupportPin}
	render(w, "support", v)
}

type settingsView struct {
	Tab           string
	IPCheck       bool
	PermSession   bool
	TwoFAActive   bool
	TwoFA         *TwoFAInit
	InvoiceData   *InvoiceData
	Countries     []UserCountry
	SSHKeys       []SSHKey
	Notifications []NotificationSetting
	Sessions      []APISession
}

var settingsTabs = map[string]bool{"general": true, "sshkeys": true, "notifications": true, "sessions": true}

// buildSettingsGeneral loads everything the General tab shows.
func buildSettingsGeneral(api API, s *session, sv *settingsView) {
	var ki struct {
		UserInfo struct {
			IPCheck      Flag `json:"ipcheck"`
			PermSessions Flag `json:"permsessions"`
			TwoFAStatus  Num  `json:"twofastatus"`
		} `json:"userInfo"`
	}
	if api.get("/user/apikey/"+url.PathEscape(s.token), &ki) == nil {
		sv.IPCheck = bool(ki.UserInfo.IPCheck)
		sv.PermSession = bool(ki.UserInfo.PermSessions)
		sv.TwoFAActive = ki.UserInfo.TwoFAStatus == 2
	}
	u := "/user/" + url.PathEscape(s.userID)
	var inv InvoiceData
	if api.get(u+"/invoicedata", &inv) == nil {
		sv.InvoiceData = &inv
	}
	api.get(u+"/countrys", &sv.Countries)
}

func settingsPage(w http.ResponseWriter, r *http.Request, s *session) {
	tab := r.URL.Query().Get("tab")
	if !settingsTabs[tab] {
		tab = "general"
	}
	api := API{token: s.token}
	u := "/user/" + url.PathEscape(s.userID)
	sv := settingsView{Tab: tab}
	switch tab {
	case "general":
		buildSettingsGeneral(api, s, &sv)
	case "sshkeys":
		api.get(u+"/sshkeys", &sv.SSHKeys)
	case "notifications":
		if err := api.get(u+"/notification/settings", &sv.Notifications); isAuthError(err) {
			apiFail(w, r, "/settings", err)
			return
		}
	case "sessions":
		api.get(u+"/sessions", &sv.Sessions)
	}
	v := vd("Settings", "settings", s, r)
	v.Data = sv
	render(w, "settings", v)
}

// userAction runs one API call for the signed-in user, then redirects with a flash.
func userAction(w http.ResponseWriter, r *http.Request, s *session, target, okMsg string,
	call func(api API, uid string) error) {
	if err := call(API{token: s.token}, url.PathEscape(s.userID)); err != nil {
		apiFail(w, r, target, err)
		return
	}
	flashOK(w, r, target, okMsg)
}

// idDelete handles the "DELETE /user/{id}<sub><posted id>" actions that differ
// only by path and flash message.
func idDelete(sub, target, okMsg string) func(http.ResponseWriter, *http.Request, *session) {
	return func(w http.ResponseWriter, r *http.Request, s *session) {
		id, ok := formUUID(w, r, "id")
		if !ok {
			return
		}
		userAction(w, r, s, target, okMsg, func(api API, uid string) error {
			return api.delete("/user/" + uid + sub + url.PathEscape(id))
		})
	}
}

// chk normalizes a checkbox to the "0"/"1" the API expects.
func chk(r *http.Request, k string) string {
	if r.PostFormValue(k) == "1" {
		return "1"
	}
	return "0"
}

func settingsAccount(w http.ResponseWriter, r *http.Request, s *session) {
	userAction(w, r, s, "/settings", "Account data saved.", func(api API, uid string) error {
		return api.post("/user/"+uid+"/", map[string]string{
			"ipcheck": chk(r, "ipcheck"), "permsessions": chk(r, "permsessions")})
	})
}

func validInvoiceField(v string, required bool) bool {
	if v == "" {
		return !required
	}
	return !badInput(v, 128)
}

var reCountryID = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

func settingsInvoiceData(w http.ResponseWriter, r *http.Request, s *session) {
	invoiceDataSubmit(w, r, s, "/settings")
}

func invoiceDataSubmit(w http.ResponseWriter, r *http.Request, s *session, target string) {
	f := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	firstname, lastname := f("firstname"), f("lastname")
	street, zip, city, company := f("street"), f("zip"), f("city"), f("company")
	country := f("country")
	if !validInvoiceField(firstname, true) || !validInvoiceField(lastname, true) ||
		!validInvoiceField(street, true) || !validInvoiceField(zip, true) ||
		!validInvoiceField(city, true) || !validInvoiceField(company, false) ||
		!reCountryID.MatchString(country) {
		http.Error(w, "invalid invoice data", http.StatusBadRequest)
		return
	}
	userAction(w, r, s, target, "Invoice data saved.", func(api API, uid string) error {
		return api.post("/user/"+uid+"/invoicedata",
			map[string]string{"firstname": firstname, "lastname": lastname, "street": street,
				"zip": zip, "city": city, "company": company, "country": country})
	})
}

func settingsTwofaInit(w http.ResponseWriter, r *http.Request, s *session) {
	api := API{token: s.token}
	var tf TwoFAInit
	if err := api.postOut("/user/"+url.PathEscape(s.userID)+"/twofa/init", nil, &tf); err != nil {
		apiFail(w, r, "/settings", err)
		return
	}
	sv := settingsView{Tab: "general", TwoFA: &tf}
	buildSettingsGeneral(api, s, &sv)
	v := vd("Settings", "settings", s, r)
	v.Data = sv
	render(w, "settings", v)
}

func settingsTwofaFinish(w http.ResponseWriter, r *http.Request, s *session) {
	code := strings.TrimSpace(r.PostFormValue("code"))
	if code == "" || len(code) > 16 {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}
	userAction(w, r, s, "/settings", "Two-factor authentication activated.", func(api API, uid string) error {
		return api.post("/user/"+uid+"/twofa/finish", map[string]string{"code": code})
	})
}

func settingsTwofaRemove(w http.ResponseWriter, r *http.Request, s *session) {
	userAction(w, r, s, "/settings", "Two-factor authentication removed.", func(api API, uid string) error {
		return api.post("/user/"+uid+"/twofa/remove", nil)
	})
}

func settingsSessionsDeleteAll(w http.ResponseWriter, r *http.Request, s *session) {
	userAction(w, r, s, "/settings?tab=sessions",
		"All official-panel sessions deleted (your panel login here is unaffected).",
		func(api API, uid string) error { return api.delete("/user/" + uid + "/sessions") })
}

/* ── server actions ── */

// serviceAction validates the id and runs one API call, then redirects back to
// the given server tab with a flash.
func serviceAction(w http.ResponseWriter, r *http.Request, s *session, tab, okMsg string,
	call func(api API, id string) error) {
	id := r.PathValue("id")
	if !reUUID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	target := "/server/" + id
	if tab != "" {
		target += "?tab=" + tab
	}
	if err := call(API{token: s.token}, url.PathEscape(id)); err != nil {
		apiFail(w, r, target, err)
		return
	}
	flashOK(w, r, target, okMsg)
}

var powerActions = map[string]bool{
	"start": true, "stop": true, "restart": true, "shutdown": true, "forcestop": true,
}

func serverPower(w http.ResponseWriter, r *http.Request, s *session) {
	action := r.PostFormValue("action")
	if !powerActions[action] {
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "", "Power command sent.", func(api API, id string) error {
		return api.post("/service/"+id+"/"+action, nil)
	})
}

func serverRename(w http.ResponseWriter, r *http.Request, s *session) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if badInput(name, 64) {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "settings", "Name updated.", func(api API, id string) error {
		return api.post("/service/"+id+"/name", map[string]string{"name": name})
	})
}

func serverHostname(w http.ResponseWriter, r *http.Request, s *session) {
	hostname := strings.TrimSpace(r.PostFormValue("hostname"))
	reset := chk(r, "reset")
	if reset == "1" {
		hostname = "reset" // the API resets to the generated default
	} else if !reHostname.MatchString(hostname) {
		http.Error(w, "invalid hostname", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "settings", "Hostname updated.", func(api API, id string) error {
		return api.post("/service/"+id+"/hostname", map[string]string{"hostname": hostname, "reset": reset})
	})
}

func serverRDNS(w http.ResponseWriter, r *http.Request, s *session) {
	ip := net.ParseIP(strings.TrimSpace(r.PostFormValue("ip")))
	rdns := strings.TrimSuffix(strings.TrimSpace(r.PostFormValue("rdns")), ".")
	if ip != nil && r.PostFormValue("reset") == "1" {
		// default rDNS like the official panel: reversed octets + .in-addr.arpa
		o := strings.Split(ip.String(), ".")
		slices.Reverse(o)
		rdns = strings.Join(o, ".") + ".in-addr.arpa"
	}
	if ip == nil || !reHostname.MatchString(rdns) {
		http.Error(w, "invalid ip or rdns", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "network", "rDNS updated.", func(api API, id string) error {
		return api.post("/service/"+id+"/ip/"+url.PathEscape(ip.String())+"/rdns",
			map[string]string{"rdns": rdns})
	})
}

func serverReinstall(w http.ResponseWriter, r *http.Request, s *session) {
	osID := r.PostFormValue("os")
	if r.PostFormValue("confirm") != "yes" || !reUUID.MatchString(osID) {
		http.Error(w, "confirmation or OS missing", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "danger", "Reinstall started — the server will be wiped and reinstalled.", func(api API, id string) error {
		return api.post("/service/"+id+"/reinstall", map[string]string{"os": osID})
	})
}

// servicePost handles the plain "POST /service/{id}/<path>, empty body" actions.
func servicePost(path, tab, okMsg string) func(http.ResponseWriter, *http.Request, *session) {
	return func(w http.ResponseWriter, r *http.Request, s *session) {
		serviceAction(w, r, s, tab, okMsg, func(api API, id string) error {
			return api.post("/service/"+id+"/"+path, nil)
		})
	}
}

// formUUID reads a POST field that has to be an id, answering 400 itself when
// it is not one.
func formUUID(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	v := r.PostFormValue(name)
	if !reUUID.MatchString(v) {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return "", false
	}
	return v, true
}

func serverBackupDelete(w http.ResponseWriter, r *http.Request, s *session) {
	b, ok := formUUID(w, r, "backup")
	if !ok {
		return
	}
	serviceAction(w, r, s, "backups", "Backup deleted.", func(api API, id string) error {
		return api.post("/service/"+id+"/backup/delete", map[string]string{"backup": b})
	})
}

func serverBackupRestore(w http.ResponseWriter, r *http.Request, s *session) {
	b, ok := formUUID(w, r, "backup")
	if !ok {
		return
	}
	serviceAction(w, r, s, "backups", "Restore started — the current disk state is being replaced.", func(api API, id string) error {
		return api.post("/service/"+id+"/backup/restore", map[string]string{"backup": b})
	})
}

var extendDays = map[string]bool{"15": true, "30": true, "60": true, "90": true}

func serverExtend(w http.ResponseWriter, r *http.Request, s *session) {
	days := r.PostFormValue("days")
	if !extendDays[days] {
		http.Error(w, "invalid extension period", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "billing", "Extension requested.", func(api API, id string) error {
		return api.post("/service/"+id+"/extend", map[string]string{"days": days, "credit": chk(r, "credit")})
	})
}

func serverAutorenew(w http.ResponseWriter, r *http.Request, s *session) {
	enable := r.PostFormValue("enable") == "1"
	msg := "Auto-renew disabled."
	if enable {
		msg = "Auto-renew enabled (paid from credit)."
	}
	serviceAction(w, r, s, "billing", msg, func(api API, id string) error {
		if enable {
			return api.post("/service/"+id+"/autorenew/credit", nil)
		}
		return api.delete("/service/" + id + "/autorenew/credit")
	})
}

// serverAutorenewPayment sets up auto-renew via PayPal/credit card; enabling
// forwards the browser to the provider to authorize the automatic payment.
func serverAutorenewPayment(w http.ResponseWriter, r *http.Request, s *session) {
	id := r.PathValue("id")
	if !reUUID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	target := "/server/" + id + "?tab=billing"
	api := API{token: s.token}
	if r.PostFormValue("enable") != "1" {
		if err := api.delete("/service/" + url.PathEscape(id) + "/autorenew/payment"); err != nil {
			apiFail(w, r, target, err)
			return
		}
		flashOK(w, r, target, "Auto-renew via payment disabled.")
		return
	}
	method := r.PostFormValue("paymentmethod")
	if method != "paypal" && method != "creditcard" {
		http.Error(w, "invalid payment method", http.StatusBadRequest)
		return
	}
	var resp struct {
		URL string `json:"url"`
	}
	if err := api.postOut("/service/"+url.PathEscape(id)+"/autorenew/payment",
		map[string]string{"paymentmethod": method}, &resp); err != nil {
		apiFail(w, r, target, err)
		return
	}
	if !strings.HasPrefix(resp.URL, "https://") {
		apiFail(w, r, target, errors.New("payment provider returned no setup link"))
		return
	}
	http.Redirect(w, r, resp.URL, http.StatusSeeOther)
}

func ipParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	ip := strings.TrimSpace(r.PostFormValue("ip"))
	if net.ParseIP(ip) == nil {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return "", false
	}
	return ip, true
}

// serverProtStatus — undocumented endpoint (used by the official panel).
func serverProtStatus(w http.ResponseWriter, r *http.Request, s *session) {
	ip, ok := ipParam(w, r)
	if !ok {
		return
	}
	status := r.PostFormValue("status")
	if status != "dynamic" && status != "permanent" {
		http.Error(w, "invalid protection status", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "network", "DDoS protection changed — this can take a few minutes to apply.",
		func(api API, id string) error {
			return api.post("/service/"+id+"/prot/status", map[string]string{"ip": ip, "status": status})
		})
}

func serverIPNote(w http.ResponseWriter, r *http.Request, s *session) {
	ip, ok := ipParam(w, r)
	if !ok {
		return
	}
	note := strings.TrimSpace(r.PostFormValue("note"))
	kind := "ip"
	if r.PostFormValue("v6") == "1" {
		kind = "ipv6"
	}
	if badInput(note, 128) {
		http.Error(w, "invalid note", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "network", "Note saved.", func(api API, id string) error {
		return api.post("/service/"+id+"/note/"+kind, map[string]string{"ip": ip, "note": note})
	})
}

// serverRDNS6Set creates or updates the rDNS entry of a single IPv6 address.
func serverRDNS6Set(w http.ResponseWriter, r *http.Request, s *session) {
	ip, ok := ipParam(w, r)
	if !ok {
		return
	}
	rdns := strings.TrimSpace(r.PostFormValue("rdns"))
	if !reHostname.MatchString(rdns) {
		http.Error(w, "invalid rdns", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "network", "IPv6 rDNS saved.", func(api API, id string) error {
		return api.post("/service/"+id+"/ip/"+url.PathEscape(ip), map[string]string{"rdns": rdns})
	})
}

func serverRDNS6Delete(w http.ResponseWriter, r *http.Request, s *session) {
	ip, ok := ipParam(w, r)
	if !ok {
		return
	}
	serviceAction(w, r, s, "network", "IPv6 rDNS entry deleted.", func(api API, id string) error {
		return api.delete("/service/" + id + "/ip/" + url.PathEscape(ip))
	})
}

func serverTrafficNotify(w http.ResponseWriter, r *http.Request, s *session) {
	serviceAction(w, r, s, "traffic", "Traffic notification setting saved.", func(api API, id string) error {
		return api.post("/service/"+id+"/traffic/notify", map[string]string{"status": chk(r, "status")})
	})
}

func serverAttackNotify(w http.ResponseWriter, r *http.Request, s *session) {
	serviceAction(w, r, s, "ddos", "DDoS notification setting saved.", func(api API, id string) error {
		return api.post("/service/"+id+"/attack/notify", map[string]string{"status": chk(r, "status")})
	})
}

// serverFeatureToggle handles TPM and UEFI add/remove, which share a URL shape.
func serverFeatureToggle(feature string) func(http.ResponseWriter, *http.Request, *session) {
	return func(w http.ResponseWriter, r *http.Request, s *session) {
		op := "remove"
		if r.PostFormValue("enable") == "1" {
			op = "add"
		}
		serviceAction(w, r, s, "hardware", strings.ToUpper(feature)+" change applied.",
			func(api API, id string) error {
				return api.post("/service/"+id+"/"+feature+"/"+op, nil)
			})
	}
}

func serverUplink(w http.ResponseWriter, r *http.Request, s *session) {
	uplink := r.PostFormValue("uplink")
	if v, err := strconv.Atoi(uplink); err != nil || v < 1 || v > 100000 {
		http.Error(w, "invalid uplink", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "hardware", "Uplink changed.", func(api API, id string) error {
		return api.post("/service/"+id+"/uplink", map[string]string{"uplink": uplink})
	})
}

func serverBackupRename(w http.ResponseWriter, r *http.Request, s *session) {
	b, ok := formUUID(w, r, "backup")
	if !ok {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" || badInput(name, 64) {
		http.Error(w, "invalid backup name", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "backups", "Backup renamed.", func(api API, id string) error {
		return api.post("/service/"+id+"/backup/rename", map[string]string{"backup": b, "name": name})
	})
}

// serverBackupLock locks (lock=1) or unlocks a backup against cron cleanup.
func serverBackupLock(w http.ResponseWriter, r *http.Request, s *session) {
	b, ok := formUUID(w, r, "backup")
	if !ok {
		return
	}
	op, msg := "unlock", "Backup unlocked — cron jobs may delete it again."
	if r.PostFormValue("lock") == "1" {
		op, msg = "lock", "Backup locked — cron jobs will not delete it."
	}
	serviceAction(w, r, s, "backups", msg, func(api API, id string) error {
		return api.post("/service/"+id+"/backup/"+b+"/"+op, nil)
	})
}

var cronActions = map[string]bool{"start": true, "stop": true, "shutdown": true, "reset": true, "backup": true}
var reCronExpr = regexp.MustCompile(`^[0-9*/,-]+ [0-9*/,-]+ [0-9*/,-]+ [0-9*/,-]+ [0-9*/,-]+$`)

func cronFields(w http.ResponseWriter, r *http.Request) (map[string]string, bool) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	expr := strings.TrimSpace(r.PostFormValue("expression"))
	action := r.PostFormValue("action")
	if name == "" || badInput(name, 64) ||
		!reCronExpr.MatchString(expr) || !cronActions[action] {
		http.Error(w, "invalid scheduled task", http.StatusBadRequest)
		return nil, false
	}
	return map[string]string{"name": name, "expression": expr, "action": action,
		"emailnotifyonfinish": chk(r, "notifyfinish"), "emailnotifyonfailure": chk(r, "notifyfailure")}, true
}

func serverCronCreate(w http.ResponseWriter, r *http.Request, s *session) {
	form, ok := cronFields(w, r)
	if !ok {
		return
	}
	serviceAction(w, r, s, "tasks", "Scheduled task created.", func(api API, id string) error {
		return api.post("/service/"+id+"/cron", form)
	})
}

func serverCronEdit(w http.ResponseWriter, r *http.Request, s *session) {
	cronID := r.PostFormValue("cron")
	form, ok := cronFields(w, r)
	if !ok {
		return
	}
	if !reToken.MatchString(cronID) {
		http.Error(w, "invalid task id", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "tasks", "Scheduled task saved.", func(api API, id string) error {
		return api.post("/service/"+id+"/cron/"+url.PathEscape(cronID), form)
	})
}

func serverCronDelete(w http.ResponseWriter, r *http.Request, s *session) {
	cronID := r.PostFormValue("cron")
	if !reToken.MatchString(cronID) {
		http.Error(w, "invalid task id", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "tasks", "Scheduled task deleted.", func(api API, id string) error {
		return api.delete("/service/" + id + "/cron/" + url.PathEscape(cronID) + "/delete")
	})
}

// scaleTrafficBars fills the bar-chart percentages relative to the series peak.
func scaleTrafficBars(pts []TrafficPoint) {
	var peak float64
	for _, p := range pts {
		peak = max(peak, max(float64(p.In), float64(p.Out)))
	}
	if peak == 0 {
		return
	}
	for i := range pts {
		pts[i].InPct = int(float64(pts[i].In) / peak * 100)
		pts[i].OutPct = int(float64(pts[i].Out) / peak * 100)
	}
}

// serverISOMountStd inserts a Datalix-provided ISO (stops the server).
func serverISOMountStd(w http.ResponseWriter, r *http.Request, s *session) {
	isoID, ok := formUUID(w, r, "iso")
	if !ok {
		return
	}
	serviceAction(w, r, s, "settings", "ISO inserted — start the server manually.", func(api API, id string) error {
		return api.post("/service/"+id+"/iso", map[string]string{"iso": isoID})
	})
}

// serverISORemove ejects a mounted ISO; this is also how rescue mode is disabled.
func serverISORemove(w http.ResponseWriter, r *http.Request, s *session) {
	serviceAction(w, r, s, "", "ISO ejected / rescue disabled.", func(api API, id string) error {
		return api.delete("/service/" + id + "/iso")
	})
}

func serverCustomISOAdd(w http.ResponseWriter, r *http.Request, s *session) {
	link := strings.TrimSpace(r.PostFormValue("url"))
	if !strings.HasPrefix(link, "https://") && !strings.HasPrefix(link, "http://") || len(link) > 512 {
		http.Error(w, "invalid iso url", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "settings", "ISO download started.", func(api API, id string) error {
		return api.post("/service/"+id+"/iso/custom", map[string]string{"url": link})
	})
}

// serverCustomISOMount mounts or unmounts a custom ISO (same endpoint toggles).
func serverCustomISOMount(w http.ResponseWriter, r *http.Request, s *session) {
	isoID, ok := formUUID(w, r, "iso")
	if !ok {
		return
	}
	serviceAction(w, r, s, "settings", "ISO mount state changed.", func(api API, id string) error {
		return api.post("/service/"+id+"/iso/custom/"+isoID+"/mount", nil)
	})
}

func serverCustomISODelete(w http.ResponseWriter, r *http.Request, s *session) {
	isoID, ok := formUUID(w, r, "iso")
	if !ok {
		return
	}
	serviceAction(w, r, s, "settings", "Custom ISO deleted.", func(api API, id string) error {
		return api.delete("/service/" + id + "/iso/custom/" + isoID)
	})
}

/* ── account actions ── */

func accountPassword(w http.ResponseWriter, r *http.Request, s *session) {
	oldPW, newPW := r.PostFormValue("oldpassword"), r.PostFormValue("newpassword")
	if oldPW == "" || len(newPW) < 8 || len(newPW) > 256 {
		http.Error(w, "password must be 8–256 characters", http.StatusBadRequest)
		return
	}
	userAction(w, r, s, "/settings", "Password changed.", func(api API, uid string) error {
		return api.post("/user/"+uid+"/changepassword",
			map[string]string{"oldpassword": oldPW, "newpassword": newPW})
	})
}

func accountSSHKeyAdd(w http.ResponseWriter, r *http.Request, s *session) {
	name := strings.TrimSpace(r.PostFormValue("displayname"))
	key := strings.TrimSpace(r.PostFormValue("key"))
	okPrefix := strings.HasPrefix(key, "ssh-") || strings.HasPrefix(key, "ecdsa-")
	if name == "" || badInput(name, 64) ||
		!okPrefix || len(key) > 4096 || strings.ContainsAny(key, "\r\n") {
		http.Error(w, "invalid SSH key", http.StatusBadRequest)
		return
	}
	userAction(w, r, s, "/settings?tab=sshkeys", "SSH key added.", func(api API, uid string) error {
		return api.post("/user/"+uid+"/sshkeys", map[string]string{"displayname": name, "key": key})
	})
}

func accountRedeem(w http.ResponseWriter, r *http.Request, s *session) {
	code := strings.TrimSpace(r.PostFormValue("code"))
	if code == "" || badInput(code, 64) {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}
	userAction(w, r, s, "/", "Code redeemed.", func(api API, uid string) error {
		return api.post("/user/"+uid+"/redeem", map[string]string{"code": code})
	})
}

func accountVerifyEmail(w http.ResponseWriter, r *http.Request, s *session) {
	userAction(w, r, s, "/", "Verification email sent — check your inbox (and spam folder).",
		func(api API, uid string) error { return api.post("/user/"+uid+"/email/verify", nil) })
}

/* ── support / settings actions ── */

func supportNewPin(w http.ResponseWriter, r *http.Request, s *session) {
	userAction(w, r, s, "/support", "New support PIN generated.",
		func(api API, uid string) error { return api.post("/user/"+uid+"/supportpin/new", nil) })
}

func validWebhookURL(raw string) bool {
	if raw == "" {
		return true
	}
	if len(raw) > 512 {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

func settingsNotify(w http.ResponseWriter, r *http.Request, s *session) {
	typ := r.PostFormValue("type")
	discord := strings.TrimSpace(r.PostFormValue("discord"))
	webhook := strings.TrimSpace(r.PostFormValue("webhook"))
	if !reNotify.MatchString(typ) || !validWebhookURL(discord) || !validWebhookURL(webhook) {
		http.Error(w, "invalid notification settings", http.StatusBadRequest)
		return
	}
	userAction(w, r, s, "/settings?tab=notifications", "Notification settings saved.",
		func(api API, uid string) error {
			return api.post("/user/"+uid+"/notification/settings/"+url.PathEscape(typ),
				map[string]string{"email": chk(r, "email"), "discord": discord, "webhook": webhook})
		})
}

/* ── polled JSON endpoints (short server-side cache to respect API rate limits) ── */

func writeJSON(w http.ResponseWriter, code int, data []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	w.Write(data)
}

// cachedAPI serves one cached service sub-endpoint as JSON.
func cachedAPI(w http.ResponseWriter, r *http.Request, s *session, kind, suffix string, ttl time.Duration, out any) {
	id := r.PathValue("id")
	if !reUUID.MatchString(id) {
		writeJSON(w, http.StatusBadRequest, []byte(`{"error":"bad id"}`))
		return
	}
	data, err := cached(s.token, kind+":"+id, ttl, func() ([]byte, error) {
		if err := (API{token: s.token}).get("/service/"+url.PathEscape(id)+suffix, out); err != nil {
			return nil, err
		}
		return json.Marshal(out)
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, []byte(`{"error":"unavailable"}`))
		return
	}
	writeJSON(w, http.StatusOK, data)
}

func apiStatus(w http.ResponseWriter, r *http.Request, s *session) {
	var st struct {
		Status string `json:"status"`
	}
	cachedAPI(w, r, s, "status", "/status", 30*time.Second, &st)
}

func apiLive(w http.ResponseWriter, r *http.Request, s *session) {
	var ld LiveData
	// livedata is rate-limited to 30 req / 15 min by Datalix — cache hard
	cachedAPI(w, r, s, "live", "/livedata", 45*time.Second, &ld)
}

/* ── generic API proxy ──────────────────────────────────────────────────
   /api/proxy/<datalix path> forwards to the Datalix API and hands the
   response straight back, so the frontend fetches this panel instead of
   backend.datalix.de. The token is attached server-side and still never
   reaches the browser.

   Reads are plain GETs. Writes carry the same CSRF and Origin checks as
   every form POST in the panel: unlike the page handlers this one reaches
   every API route there is, so the gate has to be at least as strict. */

var proxyMethods = map[string]bool{
	http.MethodGet:    true,
	http.MethodPost:   true,
	http.MethodDelete: true,
}

func proxyAPI(w http.ResponseWriter, r *http.Request) {
	s := getSession(r)
	if s == nil {
		// 401 rather than the usual redirect: fetch() cannot tell a login
		// page from data, so answer in a shape the caller can branch on
		writeJSON(w, http.StatusUnauthorized, []byte(`{"error":"not signed in"}`))
		return
	}
	if !proxyMethods[r.Method] {
		writeJSON(w, http.StatusMethodNotAllowed, []byte(`{"error":"method not allowed"}`))
		return
	}

	var form url.Values
	if r.Method != http.MethodGet {
		// raw builds the upstream multipart itself, so callers send a plain
		// form. Refuse anything else rather than forward a request with the
		// fields silently missing.
		ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if r.ContentLength != 0 && ct != "application/x-www-form-urlencoded" {
			writeJSON(w, http.StatusUnsupportedMediaType,
				[]byte(`{"error":"body must be application/x-www-form-urlencoded"}`))
			return
		}
		if !postGuard(w, r, s.csrf) {
			return
		}
		form = r.PostForm
		form.Del("csrf") // ours, not the API's
		if r.Method != http.MethodPost {
			form = nil // a DELETE carries no body at all
		}
	}

	path, ok := proxyPath(r.PathValue("path"), r.URL.Query())
	if !ok {
		writeJSON(w, http.StatusBadRequest, []byte(`{"error":"bad path"}`))
		return
	}

	data, err := API{token: s.token}.raw(r.Method, path, form)
	if err == nil {
		writeJSON(w, http.StatusOK, data)
		return
	}
	var ae *apiError
	switch {
	case isAuthError(err):
		dropSession(w, r)
		writeJSON(w, http.StatusUnauthorized, []byte(`{"error":"API key rejected"}`))
	case errors.As(err, &ae):
		body, _ := json.Marshal(map[string]string{"error": ae.msg})
		writeJSON(w, ae.status, body)
	default:
		writeJSON(w, http.StatusBadGateway, []byte(`{"error":"Datalix API unreachable"}`))
	}
}

// proxyPath rebuilds the upstream path from the wildcard segment and carries
// the caller's query string along, minus anything that could shadow our auth.
func proxyPath(rest string, q url.Values) (string, bool) {
	if rest == "" || strings.Contains(rest, "..") {
		return "", false
	}
	// PathValue hands back the decoded path, so re-escape segment by segment:
	// an encoded slash from the caller must not become a separator upstream.
	segs := strings.Split(rest, "/")
	for i, seg := range segs {
		if seg == "" {
			return "", false
		}
		segs[i] = url.PathEscape(seg)
	}
	q.Del("token") // raw appends the real one
	path := "/" + strings.Join(segs, "/")
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	return path, true
}

/* ── access manager ── */

type accessPermGroup struct {
	PID   string
	Perms []AccessPerm
	Has   map[string]bool // always nil: the create dialog starts unchecked, shared define needs the field
}

type accessRow struct {
	AccessEntry
	Date  string
	Has   map[string]bool
	Perms []AccessPerm
}

type accessView struct {
	Key      string
	Granted  []accessRow
	Requests []accessRow
	Services []Service
	Groups   []accessPermGroup
}

func accessRowOf(e AccessEntry, perms map[string][]AccessPerm) accessRow {
	row := accessRow{AccessEntry: e, Date: string(e.CreatedOn), Has: map[string]bool{},
		Perms: perms[strconv.Itoa(int(e.ProductID))]}
	row.Name = cleanName(row.Name)
	// the request list sends unix timestamps, the granted list date strings
	if n, err := strconv.ParseInt(string(e.CreatedOn), 10, 64); err == nil && n > 0 {
		row.Date = time.Unix(n, 0).UTC().Format("02.01.2006 15:04")
	}
	for _, en := range e.Entrys {
		row.Has[en.Perm] = true
	}
	return row
}

func accessPage(w http.ResponseWriter, r *http.Request, s *session) {
	api := API{token: s.token}
	u := "/user/" + url.PathEscape(s.userID)
	var granted, requests []AccessEntry
	if err := api.get(u+"/access/list", &granted); isAuthError(err) {
		apiFail(w, r, "/", err)
		return
	}
	api.get(u+"/access/list/request", &requests)
	perms := map[string][]AccessPerm{}
	api.get("/user/access/info", &perms)
	var ki struct {
		UserInfo struct {
			AccessKey string `json:"accesskey"`
		} `json:"userInfo"`
	}
	api.get("/user/apikey/"+url.PathEscape(s.token), &ki)

	av := accessView{Key: ki.UserInfo.AccessKey}
	var all []Service
	api.get("/service/list?type=active", &all)
	seen := map[string]bool{}
	for _, sv := range all {
		if int(sv.ProductID) == 3 { // webspace cannot be shared (official panel skips it too)
			continue
		}
		sv.Name = cleanName(sv.Name)
		av.Services = append(av.Services, sv)
		pid := strconv.Itoa(int(sv.ProductID))
		if !seen[pid] && len(perms[pid]) > 0 {
			seen[pid] = true
			av.Groups = append(av.Groups, accessPermGroup{PID: pid, Perms: perms[pid]})
		}
	}
	for _, e := range granted {
		av.Granted = append(av.Granted, accessRowOf(e, perms))
	}
	for _, e := range requests {
		av.Requests = append(av.Requests, accessRowOf(e, perms))
	}
	v := vd("Access", "access", s, r)
	v.Data = av
	render(w, "access", v)
}

// permsForm collects the checked permissions as the PHP-style repeated
// "permissions[]" field the backend expects.
func permsForm(r *http.Request, name string) url.Values {
	form := url.Values{"name": {name}}
	for _, p := range r.PostForm["perm"] {
		if p != "" && !badInput(p, 64) {
			form.Add("permissions[]", p)
		}
	}
	return form
}

func accessCreate(w http.ResponseWriter, r *http.Request, s *session) {
	sid := r.PostFormValue("service")
	key := strings.TrimSpace(r.PostFormValue("key"))
	name := strings.TrimSpace(r.PostFormValue("name"))
	if !reUUID.MatchString(sid) || key == "" || len(key) > 64 || len(name) > 64 {
		http.Error(w, "invalid access request", http.StatusBadRequest)
		return
	}
	form := permsForm(r, name)
	form.Set("key", key)
	if err := (API{token: s.token}).postValues("/service/"+url.PathEscape(sid)+"/access", form); err != nil {
		apiFail(w, r, "/access", err)
		return
	}
	flashOK(w, r, "/access", "Invitation sent.")
}

func accessEdit(w http.ResponseWriter, r *http.Request, s *session) {
	id := r.PostFormValue("id")
	name := strings.TrimSpace(r.PostFormValue("name"))
	if !reUUID.MatchString(id) || len(name) > 64 {
		http.Error(w, "invalid access id", http.StatusBadRequest)
		return
	}
	err := (API{token: s.token}).postValues(
		"/user/"+url.PathEscape(s.userID)+"/access/"+url.PathEscape(id), permsForm(r, name))
	if err != nil {
		apiFail(w, r, "/access", err)
		return
	}
	flashOK(w, r, "/access", "Access saved.")
}

// accessAction handles delete (verb "") plus accept/deny on an access id.
func accessAction(verb, okMsg string) func(http.ResponseWriter, *http.Request, *session) {
	return func(w http.ResponseWriter, r *http.Request, s *session) {
		id, ok := formUUID(w, r, "id")
		if !ok {
			return
		}
		userAction(w, r, s, "/access", okMsg, func(api API, uid string) error {
			p := "/user/" + uid + "/access/" + url.PathEscape(id)
			if verb == "" {
				return api.delete(p)
			}
			return api.post(p+"/"+verb, nil)
		})
	}
}

/* ── emaillog ── */

func emaillogPage(w http.ResponseWriter, r *http.Request, s *session) {
	api := API{token: s.token}
	var logs []EmailLogEntry
	if err := api.get("/user/"+url.PathEscape(s.userID)+"/email/log", &logs); isAuthError(err) {
		apiFail(w, r, "/", err)
		return
	}
	v := vd("Emaillog", "emaillog", s, r)
	v.Data = struct{ Logs []EmailLogEntry }{logs}
	render(w, "emaillog", v)
}

/* ── ssh keys, mail ports ── */

func serverSSHKeyAdd(w http.ResponseWriter, r *http.Request, s *session) {
	name := strings.TrimSpace(r.PostFormValue("displayname"))
	key := strings.TrimSpace(r.PostFormValue("key"))
	if name == "" || len(name) > 64 || key == "" || len(key) > 4096 {
		http.Error(w, "invalid ssh key", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "sshkeys", "SSH key added — restart the service to activate it.",
		func(api API, id string) error {
			return api.post("/service/"+id+"/sshkeys",
				map[string]string{"displayname": name, "key": key})
		})
}

func serverSSHKeyDelete(w http.ResponseWriter, r *http.Request, s *session) {
	keyID, ok := formUUID(w, r, "id")
	if !ok {
		return
	}
	serviceAction(w, r, s, "sshkeys", "SSH key removed.", func(api API, id string) error {
		return api.delete("/service/" + id + "/sshkeys/" + url.PathEscape(keyID))
	})
}

func serverUnlockPorts(w http.ResponseWriter, r *http.Request, s *session) {
	reason := strings.TrimSpace(r.PostFormValue("reason"))
	if reason == "" || badInput(reason, 512) {
		http.Error(w, "invalid reason", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "network", "Email ports unlocked.", func(api API, id string) error {
		return api.post("/service/"+id+"/unlockports", map[string]string{"reason": reason})
	})
}

/* ── addons + upgrades ── */

func serverAddonDelete(w http.ResponseWriter, r *http.Request, s *session) {
	addon, ok := formUUID(w, r, "addon")
	if !ok {
		return
	}
	serviceAction(w, r, s, "addons", "Addon deleted.", func(api API, id string) error {
		return api.post("/service/"+id+"/addons/"+url.PathEscape(addon)+"/delete", nil)
	})
}

// orderAndPay shares the addon/upgrade checkout: create the order with the
// caller's form, then forward to the payment provider like the official panel.
func orderAndPay(w http.ResponseWriter, r *http.Request, s *session, orderPath, tab string,
	form map[string]string) {
	id := r.PathValue("id")
	if !reUUID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	target := "/server/" + id + "?tab=" + tab
	method := payMethodByID(r.PostFormValue("method"))
	if method == nil {
		apiFail(w, r, target, errors.New("pick a payment method"))
		return
	}
	api := API{token: s.token}
	var inv InvoiceData
	api.get("/user/"+url.PathEscape(s.userID)+"/invoicedata", &inv)
	if inv.FirstName == "" || inv.LastName == "" || inv.Street == "" || inv.Zip == "" || inv.City == "" {
		apiFail(w, r, target, errors.New("Please fill in and save your invoice data first (Settings → Invoice data)."))
		return
	}
	form["credit"] = chk(r, "credit")
	form["paymentmethod"] = method.ID
	form["tax"] = string(inv.Country)
	createAndPay(w, r, api, "/service/"+url.PathEscape(id)+orderPath, form, method.ID, target)
}

func serverAddonOrder(w http.ResponseWriter, r *http.Request, s *session) {
	addon := r.PostFormValue("addon")
	amount, err := strconv.Atoi(r.PostFormValue("amount"))
	if addon == "" || len(addon) > 64 || err != nil || amount < 1 || amount > 100 {
		http.Error(w, "invalid addon order", http.StatusBadRequest)
		return
	}
	orderAndPay(w, r, s, "/addon/order", "addons",
		map[string]string{"addon": addon, "amount": strconv.Itoa(amount)})
}

func serverUpgradeOrder(w http.ResponseWriter, r *http.Request, s *session) {
	pkg := r.PostFormValue("package")
	if pkg == "" || len(pkg) > 64 {
		http.Error(w, "invalid upgrade", http.StatusBadRequest)
		return
	}
	orderAndPay(w, r, s, "/upgrade", "billing", map[string]string{"package": pkg})
}
