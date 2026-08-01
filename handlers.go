package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

/* ── input validation (trust boundary: everything from the browser) ── */

var (
	reAPIKey   = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
	reUUID     = regexp.MustCompile(`^[A-Fa-f0-9-]{8,64}$`)
	reHostname = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	reNotify   = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
	reTag      = regexp.MustCompile(`<[^>]*>`)
)

// The API's activity feed embeds the official panel's HTML markup. Strip it to
// plain text — the template escapes output anyway, so leftovers can never
// render as markup; this is purely cosmetic.
func stripTags(s string) string {
	return html.UnescapeString(reTag.ReplaceAllString(s, ""))
}

func isKVM(productDisplay string) bool {
	return strings.Contains(strings.ToUpper(productDisplay), "KVM")
}

// The API returns the literal string "null" for unnamed services.
func cleanName(s string) string {
	if s == "null" {
		return ""
	}
	return s
}

/* ── login ── */

func setLoginCSRF(w http.ResponseWriter, r *http.Request) string {
	v := randHex()
	http.SetCookie(w, &http.Cookie{Name: "dplogin", Value: v, Path: "/login",
		MaxAge: 900, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: isHTTPS(r)})
	return v
}

func renderLogin(w http.ResponseWriter, r *http.Request, errMsg string, code int) {
	csrf := setLoginCSRF(w, r)
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
	renderLogin(w, r, r.URL.Query().Get("err"), http.StatusOK)
}

func loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !allowLogin(r.RemoteAddr) {
		renderLogin(w, r, "Too many attempts — wait a few minutes.", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !originOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	c, err := r.Cookie("dplogin")
	got := r.PostFormValue("csrf")
	if err != nil || len(c.Value) != 64 || got == "" ||
		subtle.ConstantTimeCompare([]byte(got), []byte(c.Value)) != 1 {
		renderLogin(w, r, "Form expired — please try again.", http.StatusForbidden)
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
	v.Msg = r.URL.Query().Get("msg")
	v.Err = r.URL.Query().Get("err")
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
	Username   string
	EmailState int // 0=unverified, 1=verified, 2=throwaway
	Servers    []Service
	Others     []Service
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
		if v.Err == "" {
			v.Err = err.Error()
		}
	}
	ov := overviewView{Greeting: greeting(), Username: s.username}
	for i := range all {
		all[i].Name = cleanName(all[i].Name)
		if isKVM(all[i].ProductDisplay) {
			ov.Servers = append(ov.Servers, all[i])
		} else {
			ov.Others = append(ov.Others, all[i])
		}
	}
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
	if len(q) > 64 || strings.ContainsFunc(q, unicode.IsControl) {
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
		if v.Err == "" {
			v.Err = err.Error()
		}
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
	ID       string
	Tab      string
	Info     ServiceInfo
	Hardware *Hardware
	IPs      *ServiceIPs
	Traffic  *TrafficHistory
	Backups  []Backup
	OSList   []OSEntry
	Logs     []ActionLog
}

var serverTabs = map[string]bool{"network": true, "hardware": true, "live": true,
	"traffic": true, "backups": true, "logs": true, "settings": true, "billing": true, "danger": true}

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
	if !isKVM(info.Service.ProductDisplay) {
		http.NotFound(w, r) // this panel manages KVM servers only
		return
	}
	info.Service.Name = cleanName(info.Service.Name)

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
				sv.Traffic = &tr
			}
		}
	case "backups":
		if info.Display.Backup {
			api.get("/service/"+pid+"/backup", &sv.Backups)
		}
	case "logs":
		api.get("/service/"+pid+"/actionlogs", &sv.Logs)
	case "danger":
		api.get("/service/"+pid+"/os", &sv.OSList)
	}

	v := vd("Server", "services", s, r)
	v.Data = sv
	render(w, "server", v)
}

type accountView struct {
	Invoices  []Invoice
	Orders    []Order
	CreditLog []CreditLogEntry
}

func accountPage(w http.ResponseWriter, r *http.Request, s *session) {
	api := API{token: s.token}
	u := "/user/" + url.PathEscape(s.userID)

	av := accountView{}
	if err := api.get(u+"/invoice/list", &av.Invoices); isAuthError(err) {
		apiFail(w, r, "/account", err)
		return
	}
	api.get(u+"/orders", &av.Orders)
	api.get(u+"/credit/log", &av.CreditLog)

	v := vd("Account", "account", s, r)
	v.Data = av
	render(w, "account", v)
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
	if title == "" || len(title) > 128 || strings.ContainsFunc(title, unicode.IsControl) ||
		text == "" || len(text) > 10000 {
		http.Error(w, "invalid ticket data", http.StatusBadRequest)
		return
	}
	if service != "" && service != "none" && !reUUID.MatchString(service) {
		http.Error(w, "invalid service", http.StatusBadRequest)
		return
	}
	if service == "" {
		service = "none"
	}
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
	Lang          string
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
	sv.Lang = "en"
	var ki struct {
		UserInfo struct {
			Lang         string `json:"lang"`
			IPCheck      Flag   `json:"ipcheck"`
			PermSessions Flag   `json:"permsessions"`
			TwoFAStatus  Num    `json:"twofastatus"`
		} `json:"userInfo"`
	}
	if api.get("/user/apikey/"+url.PathEscape(s.token), &ki) == nil {
		if ki.UserInfo.Lang != "" {
			sv.Lang = ki.UserInfo.Lang
		}
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

var validLangs = map[string]bool{"de": true, "en": true}

// userAction runs one API call for the signed-in user, then redirects with a flash.
func userAction(w http.ResponseWriter, r *http.Request, s *session, target, okMsg string,
	call func(api API, uid string) error) {
	if err := call(API{token: s.token}, url.PathEscape(s.userID)); err != nil {
		apiFail(w, r, target, err)
		return
	}
	flashOK(w, r, target, okMsg)
}

// chk normalizes a checkbox to the "0"/"1" the API expects.
func chk(r *http.Request, k string) string {
	if r.PostFormValue(k) == "1" {
		return "1"
	}
	return "0"
}

func settingsAccount(w http.ResponseWriter, r *http.Request, s *session) {
	lang := r.PostFormValue("lang")
	if !validLangs[lang] {
		http.Error(w, "invalid language", http.StatusBadRequest)
		return
	}
	userAction(w, r, s, "/settings", "Account data saved.", func(api API, uid string) error {
		return api.post("/user/"+uid+"/", map[string]string{"lang": lang,
			"ipcheck": chk(r, "ipcheck"), "permsessions": chk(r, "permsessions")})
	})
}

func validInvoiceField(v string, required bool) bool {
	if v == "" {
		return !required
	}
	return len(v) <= 128 && !strings.ContainsFunc(v, unicode.IsControl)
}

var reCountryID = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

func settingsInvoiceData(w http.ResponseWriter, r *http.Request, s *session) {
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
	userAction(w, r, s, "/settings", "Invoice data saved.", func(api API, uid string) error {
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

func settingsSessionDelete(w http.ResponseWriter, r *http.Request, s *session) {
	id := r.PostFormValue("id")
	if !reUUID.MatchString(id) {
		http.Error(w, "invalid session id", http.StatusBadRequest)
		return
	}
	userAction(w, r, s, "/settings?tab=sessions", "Session deleted.", func(api API, uid string) error {
		return api.delete("/user/" + uid + "/sessions/" + url.PathEscape(id))
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

var powerActions = map[string]string{
	"start": "/start", "stop": "/stop", "restart": "/restart",
	"shutdown": "/shutdown", "forcestop": "/forcestop",
}

func serverPower(w http.ResponseWriter, r *http.Request, s *session) {
	path, ok := powerActions[r.PostFormValue("action")]
	if !ok {
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "", "Power command sent.", func(api API, id string) error {
		return api.post("/service/"+id+path, nil)
	})
}

func serverRename(w http.ResponseWriter, r *http.Request, s *session) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if len(name) > 64 || strings.ContainsFunc(name, unicode.IsControl) {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "settings", "Name updated.", func(api API, id string) error {
		return api.post("/service/"+id+"/name", map[string]string{"name": name})
	})
}

func serverHostname(w http.ResponseWriter, r *http.Request, s *session) {
	hostname := strings.TrimSpace(r.PostFormValue("hostname"))
	if !reHostname.MatchString(hostname) {
		http.Error(w, "invalid hostname", http.StatusBadRequest)
		return
	}
	serviceAction(w, r, s, "settings", "Hostname updated.", func(api API, id string) error {
		return api.post("/service/"+id+"/hostname", map[string]string{"hostname": hostname, "reset": "0"})
	})
}

func serverRDNS(w http.ResponseWriter, r *http.Request, s *session) {
	ip := net.ParseIP(strings.TrimSpace(r.PostFormValue("ip")))
	rdns := strings.TrimSuffix(strings.TrimSpace(r.PostFormValue("rdns")), ".")
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

func serverResetPassword(w http.ResponseWriter, r *http.Request, s *session) {
	serviceAction(w, r, s, "danger", "Password reset requested — check the action log.", func(api API, id string) error {
		return api.post("/service/"+id+"/resetpassword", nil)
	})
}

func serverRescue(w http.ResponseWriter, r *http.Request, s *session) {
	serviceAction(w, r, s, "danger", "Rescue mode requested.", func(api API, id string) error {
		return api.post("/service/"+id+"/rescue", nil)
	})
}

func serverBackupCreate(w http.ResponseWriter, r *http.Request, s *session) {
	serviceAction(w, r, s, "backups", "Backup started.", func(api API, id string) error {
		return api.post("/service/"+id+"/backup", nil)
	})
}

func backupParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	b := r.PostFormValue("backup")
	if !reUUID.MatchString(b) {
		http.Error(w, "invalid backup id", http.StatusBadRequest)
		return "", false
	}
	return b, true
}

func serverBackupDelete(w http.ResponseWriter, r *http.Request, s *session) {
	b, ok := backupParam(w, r)
	if !ok {
		return
	}
	serviceAction(w, r, s, "backups", "Backup deleted.", func(api API, id string) error {
		return api.post("/service/"+id+"/backup/delete", map[string]string{"backup": b})
	})
}

func serverBackupRestore(w http.ResponseWriter, r *http.Request, s *session) {
	b, ok := backupParam(w, r)
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
	if name == "" || len(name) > 64 || strings.ContainsFunc(name, unicode.IsControl) ||
		!okPrefix || len(key) > 4096 || strings.ContainsAny(key, "\r\n") {
		http.Error(w, "invalid SSH key", http.StatusBadRequest)
		return
	}
	userAction(w, r, s, "/settings?tab=sshkeys", "SSH key added.", func(api API, uid string) error {
		return api.post("/user/"+uid+"/sshkeys", map[string]string{"displayname": name, "key": key})
	})
}

func accountSSHKeyDelete(w http.ResponseWriter, r *http.Request, s *session) {
	id := r.PostFormValue("id")
	if !reUUID.MatchString(id) {
		http.Error(w, "invalid key id", http.StatusBadRequest)
		return
	}
	userAction(w, r, s, "/settings?tab=sshkeys", "SSH key deleted.", func(api API, uid string) error {
		return api.delete("/user/" + uid + "/sshkeys/" + url.PathEscape(id))
	})
}

func accountRedeem(w http.ResponseWriter, r *http.Request, s *session) {
	code := strings.TrimSpace(r.PostFormValue("code"))
	if code == "" || len(code) > 64 || strings.ContainsFunc(code, unicode.IsControl) {
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
