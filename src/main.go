package main

// Datalix client panel — single binary, stdlib only.
// Security model: the Datalix API key lives exclusively in server memory,
// tied to a random session cookie. Every POST requires a per-session CSRF
// token; templates auto-escape; the binary executes nothing and writes no files.

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

//go:embed templates static
var assets embed.FS

/* ── sessions ── */

const sessionTTL = 12 * time.Hour

type session struct {
	token    string // Datalix API key — never sent to the browser
	userID   string
	username string
	csrf     string
	expires  time.Time
}

var (
	sessMu   sync.Mutex
	sessions = map[string]*session{}
)

func randHex() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // no entropy = no security; refuse to run
	}
	return hex.EncodeToString(b)
}

func newSession(token, userID, username string) (id string) {
	id = randHex()
	sessMu.Lock()
	defer sessMu.Unlock()
	// prune expired while we're here
	maps.DeleteFunc(sessions, func(_ string, v *session) bool { return time.Now().After(v.expires) })
	sessions[id] = &session{token: token, userID: userID, username: username,
		csrf: randHex(), expires: time.Now().Add(sessionTTL)}
	return
}

func getSession(r *http.Request) *session {
	c, err := r.Cookie("dpsess")
	if err != nil || len(c.Value) != 64 {
		return nil
	}
	sessMu.Lock()
	defer sessMu.Unlock()
	s := sessions[c.Value]
	if s == nil || time.Now().After(s.expires) {
		delete(sessions, c.Value)
		return nil
	}
	s.expires = time.Now().Add(sessionTTL) // sliding expiry
	return s
}

func dropSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("dpsess"); err == nil {
		sessMu.Lock()
		delete(sessions, c.Value)
		sessMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "dpsess", Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, id string) {
	http.SetCookie(w, &http.Cookie{
		Name: "dpsess", Value: id, Path: "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: isHTTPS(r),
	})
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

/* ── login rate limiting ── */

var (
	loginMu   sync.Mutex
	loginHits = map[string][]time.Time{}
)

// allowLogin permits 5 attempts per 5 minutes per client IP.
func allowLogin(remoteAddr string) bool {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}
	now := time.Now()
	loginMu.Lock()
	defer loginMu.Unlock()
	keep := slices.DeleteFunc(loginHits[ip], func(t time.Time) bool { return now.Sub(t) >= 5*time.Minute })
	if len(keep) >= 5 {
		loginHits[ip] = keep
		return false
	}
	loginHits[ip] = append(keep, now)
	if len(loginHits) > 10000 { // ponytail: crude flush guards memory; per-entry GC if it ever matters
		loginHits = map[string][]time.Time{}
	}
	return true
}

/* ── short server-side cache for the polled JSON endpoints ── */

type cacheEntry struct {
	data []byte
	exp  time.Time
}

var (
	cacheMu sync.Mutex
	cache   = map[string]cacheEntry{}
)

func cached(token, key string, ttl time.Duration, fill func() ([]byte, error)) ([]byte, error) {
	k := token + "|" + key
	cacheMu.Lock()
	if e, ok := cache[k]; ok && time.Now().Before(e.exp) {
		cacheMu.Unlock()
		return e.data, nil
	}
	cacheMu.Unlock()
	data, err := fill()
	if err != nil {
		return nil, err
	}
	cacheMu.Lock()
	maps.DeleteFunc(cache, func(_ string, cv cacheEntry) bool { return time.Now().After(cv.exp) })
	cache[k] = cacheEntry{data: data, exp: time.Now().Add(ttl)}
	cacheMu.Unlock()
	return data, nil
}

/* ── templates ── */

func fmtTS(ts int64, layout string) string {
	if ts <= 0 {
		return "—"
	}
	return time.Unix(ts, 0).UTC().Format(layout)
}

var tmplFuncs = template.FuncMap{
	"fmtUnix": func(ts int64) string { return fmtTS(ts, "02.01.2006") },
	"gib":     func(mb int) string { return fmt.Sprintf("%g", float64(mb)/1024) },
	"gb":      func(mb Num) string { return fmt.Sprintf("%.2f", float64(mb)/1024) },
	"daysLeft": func(ts int64) string {
		if ts <= 0 {
			return "—"
		}
		d := time.Until(time.Unix(ts, 0))
		if d <= 0 {
			return "expired"
		}
		return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	},
	"fmtUnixTime": func(ts int64) string { return fmtTS(ts, "15:04 02.01.2006") },
	// the 2FA QR code arrives as an API-supplied data URI; only allow it
	// through as an image if it is verifiably a base64 PNG
	"qrURL": func(s string) template.URL {
		const p = "data:image/png;base64,"
		if strings.HasPrefix(s, p) {
			if _, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, p)); err == nil {
				return template.URL(s)
			}
		}
		return ""
	},
	// map the official panel's tailwind badge colors onto our chip classes
	"ticketClass": func(bg string) string {
		switch {
		case strings.HasPrefix(bg, "lime"), strings.HasPrefix(bg, "green"):
			return "ok"
		case strings.HasPrefix(bg, "red"):
			return "err"
		case strings.HasPrefix(bg, "yellow"), strings.HasPrefix(bg, "amber"), strings.HasPrefix(bg, "orange"):
			return "warn"
		}
		return ""
	},
	"pctCap": func(v float64) string {
		if v < 0 {
			v = 0
		}
		if v > 100 {
			v = 100
		}
		return fmt.Sprintf("%.1f", v)
	},
	"list": func(items ...string) []string { return items },
}

var (
	pages     = map[string]*template.Template{}
	loginTmpl *template.Template
)

func initTemplates() {
	for _, p := range []string{"overview", "services", "server", "account", "support", "settings", "tickets", "ticket_new", "orders", "transactions", "donations", "affiliate", "credit", "paybyinvoice", "order", "order_config", "access", "emaillog", "ticket_view"} {
		pages[p] = template.Must(template.New("base.html").Funcs(tmplFuncs).
			ParseFS(assets, "templates/base.html", "templates/"+p+".html"))
	}
	loginTmpl = template.Must(template.New("login.html").Funcs(tmplFuncs).
		ParseFS(assets, "templates/login.html"))
}

type viewData struct {
	Title string
	Page  string
	CSRF  string
	User  string
	Msg   string
	Err   string
	Data  any
}

func render(w http.ResponseWriter, page string, vd viewData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages[page].ExecuteTemplate(w, "base", vd); err != nil {
		log.Printf("template %s: %v", page, err)
	}
}

/* ── middleware ── */

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; "+
				"font-src 'self'; img-src 'self' data:; connect-src 'self'; "+
				// form-action allows https: because the top-up POST answers with a
				// redirect to the payment provider, and some browsers re-check
				// form-action against redirect targets
				"form-action 'self' https:; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// requireAuth wraps a handler with session lookup and, on POST, CSRF + origin checks.
func requireAuth(fn func(http.ResponseWriter, *http.Request, *session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := getSession(r)
		if s == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			if !postGuard(w, r, s.csrf) {
				return
			}
		}
		fn(w, r, s)
	}
}

// postGuard enforces body size, same-origin and CSRF on form POSTs.
func postGuard(w http.ResponseWriter, r *http.Request, wantCSRF string) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	if !originOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	got := r.PostFormValue("csrf")
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(wantCSRF)) != 1 {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return false
	}
	return true
}

// originOK verifies the Origin header (when present) against the host the
// request was addressed to, honoring reverse-proxy forwarding headers.
func originOK(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" || o == "null" {
		return true // non-CORS navigation; the CSRF token is the primary defense
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	for _, h := range []string{r.Host, r.Header.Get("X-Forwarded-Host")} {
		if h != "" && strings.EqualFold(u.Host, h) {
			return true
		}
	}
	log.Printf("rejected cross-origin POST: origin=%q host=%q xfh=%q",
		o, r.Host, r.Header.Get("X-Forwarded-Host"))
	return false
}

// apiFail redirects back with the API error as a flash message; auth failures
// (revoked key, expired token) drop the panel session entirely.
func apiFail(w http.ResponseWriter, r *http.Request, target string, err error) {
	if isAuthError(err) {
		dropSession(w, r)
		http.Redirect(w, r, "/login?err="+url.QueryEscape("Your API key was rejected — please sign in again."), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, target+flashSep(target)+"err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
}

func flashOK(w http.ResponseWriter, r *http.Request, target, msg string) {
	http.Redirect(w, r, target+flashSep(target)+"msg="+url.QueryEscape(msg), http.StatusSeeOther)
}

func flashSep(target string) string {
	if strings.Contains(target, "?") {
		return "&"
	}
	return "?"
}

/* ── server ── */

func newMux() http.Handler {
	mux := http.NewServeMux()

	// static (embedded). Fonts never change; CSS/JS must revalidate so UI
	// updates aren't hidden by heuristic browser caching (embedded files
	// carry no Last-Modified).
	fileServer := http.FileServerFS(assets)
	mux.Handle("GET /static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/fonts/") {
			w.Header().Set("Cache-Control", "public, max-age=86400")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	}))

	// auth
	mux.HandleFunc("GET /login", loginPage)
	mux.HandleFunc("POST /login", loginSubmit)
	mux.HandleFunc("POST /logout", requireAuth(func(w http.ResponseWriter, r *http.Request, s *session) {
		dropSession(w, r)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}))

	// pages
	mux.HandleFunc("GET /{$}", requireAuth(overviewPage))
	mux.HandleFunc("GET /services", requireAuth(servicesPage))
	mux.HandleFunc("POST /services/{id}/fav", requireAuth(servicesFav))
	mux.HandleFunc("POST /services/{id}/hide", requireAuth(servicesHide))
	mux.HandleFunc("GET /server/{id}", requireAuth(serverPage))
	mux.HandleFunc("GET /account", requireAuth(accountPage))
	mux.HandleFunc("GET /orders", requireAuth(ordersPage))
	mux.HandleFunc("GET /transactions", requireAuth(transactionsPage))
	mux.HandleFunc("GET /invoice/{id}", requireAuth(invoiceView))
	mux.HandleFunc("GET /donations", requireAuth(donationsPage))
	mux.HandleFunc("POST /donations/create", requireAuth(donationLinkCreate))
	mux.HandleFunc("POST /donations/delete", requireAuth(donationLinkDelete))
	mux.HandleFunc("GET /affiliate", requireAuth(affiliatePage))
	mux.HandleFunc("POST /affiliate/create", requireAuth(affiliateLinkCreate))
	mux.HandleFunc("POST /affiliate/delete", requireAuth(affiliateLinkDelete))
	mux.HandleFunc("GET /credit", requireAuth(creditPage))
	mux.HandleFunc("POST /credit/topup", requireAuth(creditTopup))
	mux.HandleFunc("POST /credit/invoicedata", requireAuth(creditInvoiceData))
	mux.HandleFunc("GET /paybyinvoice", requireAuth(paybyinvoicePage))
	mux.HandleFunc("POST /paybyinvoice/create", requireAuth(pbiCreate))
	mux.HandleFunc("POST /paybyinvoice/rename", requireAuth(pbiRename))
	mux.HandleFunc("POST /paybyinvoice/reassign", requireAuth(pbiReassign))
	mux.HandleFunc("POST /paybyinvoice/pay", requireAuth(pbiPay))
	mux.HandleFunc("GET /order", requireAuth(orderPage))
	mux.HandleFunc("GET /order/{packet}", requireAuth(orderConfigPage))
	mux.HandleFunc("POST /order/{packet}", requireAuth(orderSubmit))
	mux.HandleFunc("GET /tickets", requireAuth(ticketsPage))
	mux.HandleFunc("GET /tickets/new", requireAuth(ticketNewPage))
	mux.HandleFunc("POST /tickets/new", requireAuth(ticketCreate))
	mux.HandleFunc("GET /tickets/{id}", requireAuth(ticketViewPage))
	mux.HandleFunc("POST /tickets/{id}/answer", requireAuth(ticketAnswer))
	mux.HandleFunc("GET /support", requireAuth(supportPage))
	mux.HandleFunc("GET /settings", requireAuth(settingsPage))
	mux.HandleFunc("GET /access", requireAuth(accessPage))
	mux.HandleFunc("POST /access/create", requireAuth(accessCreate))
	mux.HandleFunc("POST /access/edit", requireAuth(accessEdit))
	mux.HandleFunc("POST /access/delete", requireAuth(accessAction("", "Access deleted.")))
	mux.HandleFunc("POST /access/accept", requireAuth(accessAction("accept", "Access request accepted.")))
	mux.HandleFunc("POST /access/deny", requireAuth(accessAction("deny", "Access request denied.")))
	mux.HandleFunc("GET /emaillog", requireAuth(emaillogPage))

	// server actions
	mux.HandleFunc("POST /server/{id}/power", requireAuth(serverPower))
	mux.HandleFunc("POST /server/{id}/rename", requireAuth(serverRename))
	mux.HandleFunc("POST /server/{id}/hostname", requireAuth(serverHostname))
	mux.HandleFunc("POST /server/{id}/rdns", requireAuth(serverRDNS))
	mux.HandleFunc("POST /server/{id}/reinstall", requireAuth(serverReinstall))
	mux.HandleFunc("POST /server/{id}/resetpassword", requireAuth(servicePost("resetpassword", "danger", "Password reset requested — check the action log.")))
	mux.HandleFunc("POST /server/{id}/rescue", requireAuth(servicePost("rescue", "danger", "Rescue mode requested.")))
	mux.HandleFunc("POST /server/{id}/backup", requireAuth(servicePost("backup", "backups", "Backup started.")))
	mux.HandleFunc("POST /server/{id}/backup/delete", requireAuth(serverBackupDelete))
	mux.HandleFunc("POST /server/{id}/backup/restore", requireAuth(serverBackupRestore))
	mux.HandleFunc("POST /server/{id}/extend", requireAuth(serverExtend))
	mux.HandleFunc("POST /server/{id}/autorenew", requireAuth(serverAutorenew))
	mux.HandleFunc("POST /server/{id}/autorenew/payment", requireAuth(serverAutorenewPayment))
	mux.HandleFunc("POST /server/{id}/protstatus", requireAuth(serverProtStatus))
	mux.HandleFunc("POST /server/{id}/ipnote", requireAuth(serverIPNote))
	mux.HandleFunc("POST /server/{id}/rdns6", requireAuth(serverRDNS6Set))
	mux.HandleFunc("POST /server/{id}/rdns6/delete", requireAuth(serverRDNS6Delete))
	mux.HandleFunc("POST /server/{id}/trafficnotify", requireAuth(serverTrafficNotify))
	mux.HandleFunc("POST /server/{id}/attacknotify", requireAuth(serverAttackNotify))
	mux.HandleFunc("POST /server/{id}/tpm", requireAuth(serverFeatureToggle("tpm")))
	mux.HandleFunc("POST /server/{id}/uefi", requireAuth(serverFeatureToggle("uefi")))
	mux.HandleFunc("POST /server/{id}/uplink", requireAuth(serverUplink))
	mux.HandleFunc("POST /server/{id}/backup/rename", requireAuth(serverBackupRename))
	mux.HandleFunc("POST /server/{id}/backup/lock", requireAuth(serverBackupLock))
	mux.HandleFunc("POST /server/{id}/cron", requireAuth(serverCronCreate))
	mux.HandleFunc("POST /server/{id}/cron/edit", requireAuth(serverCronEdit))
	mux.HandleFunc("POST /server/{id}/cron/delete", requireAuth(serverCronDelete))
	mux.HandleFunc("POST /server/{id}/iso/mount", requireAuth(serverISOMountStd))
	mux.HandleFunc("POST /server/{id}/iso/remove", requireAuth(serverISORemove))
	mux.HandleFunc("POST /server/{id}/iso/custom", requireAuth(serverCustomISOAdd))
	mux.HandleFunc("POST /server/{id}/iso/custom/mount", requireAuth(serverCustomISOMount))
	mux.HandleFunc("POST /server/{id}/iso/custom/delete", requireAuth(serverCustomISODelete))
	mux.HandleFunc("POST /server/{id}/sshkey", requireAuth(serverSSHKeyAdd))
	mux.HandleFunc("POST /server/{id}/sshkey/delete", requireAuth(serverSSHKeyDelete))
	mux.HandleFunc("POST /server/{id}/unlockports", requireAuth(serverUnlockPorts))
	mux.HandleFunc("POST /server/{id}/addon/order", requireAuth(serverAddonOrder))
	mux.HandleFunc("POST /server/{id}/addon/delete", requireAuth(serverAddonDelete))
	mux.HandleFunc("POST /server/{id}/upgrade", requireAuth(serverUpgradeOrder))
	mux.HandleFunc("POST /server/{id}/backup/cancel", requireAuth(servicePost("cancelplannedbackup", "backups", "Planned backup canceled.")))

	// account / support / settings actions
	mux.HandleFunc("POST /account/password", requireAuth(accountPassword))
	mux.HandleFunc("POST /account/sshkey", requireAuth(accountSSHKeyAdd))
	mux.HandleFunc("POST /account/sshkey/delete", requireAuth(accountSSHKeyDelete))
	mux.HandleFunc("POST /account/redeem", requireAuth(accountRedeem))
	mux.HandleFunc("POST /account/verifyemail", requireAuth(accountVerifyEmail))
	mux.HandleFunc("POST /support/pin", requireAuth(supportNewPin))
	mux.HandleFunc("POST /settings/notify", requireAuth(settingsNotify))
	mux.HandleFunc("POST /settings/account", requireAuth(settingsAccount))
	mux.HandleFunc("POST /settings/invoicedata", requireAuth(settingsInvoiceData))
	mux.HandleFunc("POST /settings/twofa/init", requireAuth(settingsTwofaInit))
	mux.HandleFunc("POST /settings/twofa/finish", requireAuth(settingsTwofaFinish))
	mux.HandleFunc("POST /settings/twofa/remove", requireAuth(settingsTwofaRemove))
	mux.HandleFunc("POST /settings/session/delete", requireAuth(settingsSessionDelete))
	mux.HandleFunc("POST /settings/sessions/deleteall", requireAuth(settingsSessionsDeleteAll))

	// polled JSON
	mux.HandleFunc("GET /api/server/{id}/status", requireAuth(apiStatus))
	mux.HandleFunc("GET /api/server/{id}/live", requireAuth(apiLive))

	return secureHeaders(mux)
}

func main() {
	initTemplates()

	addr := os.Getenv("PANEL_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8480"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           newMux(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	log.Printf("nothix panel listening on http://%s (put TLS in front for production)", addr)
	log.Fatal(srv.ListenAndServe())
}
