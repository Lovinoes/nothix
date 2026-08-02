package main

// Minimal Datalix API client. Auth is a token query parameter; POST bodies are
// multipart/form-data (per the OpenAPI spec at backend.datalix.de/v1).

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// var, not const, so tests can point it at a mock server.
var apiBase = "https://backend.datalix.de/v1"

var apiHTTP = &http.Client{Timeout: 20 * time.Second}

type API struct{ token string }

func (a API) get(path string, out any) error { return a.do(http.MethodGet, path, nil, out) }
func (a API) delete(path string) error       { return a.do(http.MethodDelete, path, nil, nil) }
func (a API) post(path string, form map[string]string) error {
	return a.do(http.MethodPost, path, toValues(form), nil)
}
func (a API) postOut(path string, form map[string]string, out any) error {
	return a.do(http.MethodPost, path, toValues(form), out)
}

// postValues posts a form that may repeat keys (PHP-style arrays, "perm[]").
func (a API) postValues(path string, form url.Values) error {
	return a.do(http.MethodPost, path, form, nil)
}

func toValues(form map[string]string) url.Values {
	v := url.Values{}
	for k, val := range form {
		v.Set(k, val)
	}
	return v
}

func (a API) do(method, path string, form url.Values, out any) error {
	data, err := a.raw(method, path, form)
	if err != nil {
		return err
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return errors.New("unexpected API response")
		}
	}
	return nil
}

// raw performs the request and returns the response body undecoded.
func (a API) raw(method, path string, form url.Values) ([]byte, error) {
	u := apiBase + path + flashSep(path) + "token=" + url.QueryEscape(a.token)

	var body io.Reader
	contentType := ""
	if form != nil {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for k, vs := range form {
			for _, v := range vs {
				mw.WriteField(k, v)
			}
		}
		mw.Close()
		body = &buf
		contentType = mw.FormDataContentType()
	}

	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := apiHTTP.Do(req)
	if err != nil {
		return nil, errors.New("Datalix API unreachable")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, errors.New("Datalix API read error")
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(data, &e)
		msg := cmp.Or(e.Error, "API error (HTTP "+strconv.Itoa(resp.StatusCode)+")")
		return nil, &apiError{msg: msg, status: resp.StatusCode}
	}
	return data, nil
}

type apiError struct {
	msg    string
	status int
}

func (e *apiError) Error() string { return e.msg }

// isAuthError reports whether the API rejected our token/session.
func isAuthError(err error) bool {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.status == 401 || strings.Contains(strings.ToLower(ae.msg), "invalid session")
	}
	return false
}

/* ── tolerant JSON scalar types ─────────────────────────────────────────
   The API mixes booleans/ints and numbers/strings across endpoints, so these
   accept either form instead of failing the whole page. */

type Flag bool

func (f *Flag) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	*f = s == "1" || s == "true"
	return nil
}

type Num float64

func (n *Num) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		*n = 0
		return nil
	}
	*n = Num(v)
	return nil
}

// Str decodes JSON values that may arrive as string or number (e.g. country ids).
type Str string

func (s *Str) UnmarshalJSON(b []byte) error {
	t := strings.Trim(string(b), `"`)
	if t == "null" {
		t = ""
	}
	*s = Str(t)
	return nil
}

/* ── response models (only fields the panel renders) ─────────────────── */

type Service struct {
	ID               string `json:"id"`
	DeleteAt         int64  `json:"delete_at"`
	ExpireAt         int64  `json:"expire_at"`
	Name             string `json:"name"`
	Price            Num    `json:"price"`
	ProductDisplay   string `json:"productdisplay"`
	IP               string `json:"ip"`
	Domain           string `json:"domain"`
	ProductID        Num    `json:"productid"`
	Fav              Flag   `json:"fav"`
	Locked           Flag   `json:"locked"`
	LockReason       string `json:"lockreason"`
	DeleteDone       Flag   `json:"deletedone"`
	AutoRenew        Flag   `json:"autorenew"`
	AutoRenewPayment Str    `json:"autorenewpayment"` // "0" = off, otherwise the payment method
	AttackNotify     Flag   `json:"attacknotify"`
	Addons           Flag   `json:"addons"` // addon tab available
}

type ServiceInfo struct {
	Display struct {
		Backup    Flag `json:"backup"`
		Hardware  Flag `json:"hardware"`
		IP        Flag `json:"ip"`
		LiveData  Flag `json:"livedata"`
		Traffic   Flag `json:"traffic"`
		Cron      Flag `json:"cron"`
		DDoSLog   Flag `json:"ddoslog"`
		CustomISO Flag `json:"customisomount"`
		ISOMount  Flag `json:"isomount"`
		NoVNC     Flag `json:"novnc"`
		SSHKeys   Flag `json:"sshkeys"`
		// per-product gates for the action sidebar
		ActionButtons Flag `json:"actionbuttons"`
		LoginData     Flag `json:"logindata"`
		Renew         Flag `json:"renew"`
		Rescue        Flag `json:"rescue"`
		PasswordReset Flag `json:"passwordreset"`
	} `json:"display"`
	Product struct {
		MAC             string `json:"mac"`
		Status          string `json:"status"`
		User            string `json:"user"`
		Password        string `json:"password"`
		Hostname        string `json:"hostname"`
		Node            string `json:"node"`
		Location        string `json:"location"`
		ProxmoxID       Num    `json:"proxmoxid"`
		Rescue          Flag   `json:"rescue"`
		ConfigChanged   Flag   `json:"configchanged"`
		TrafficLimitHit Flag   `json:"trafficlimitreached"`
		PortBlock       Flag   `json:"portblock"`
		CanUnlockPorts  Flag   `json:"canunlockports"`
		OSType          string `json:"ostype"`
		TrafficNotify   Num    `json:"trafficnotify"` // 1 = email notifications on
		ISO             Flag   `json:"iso"`           // an ISO is currently inserted
		Uplink          Num    `json:"uplink"`        // tenths of MB/s (official UI divides by 10)
		MaxUplink       Num    `json:"maxuplink"`
		ClusterInfo     struct {
			DisplayName string `json:"displayname"`
		} `json:"clusterinfo"`
	} `json:"product"`
	Service Service `json:"service"`
}

type Hardware struct {
	Cores          int    `json:"cores"`
	Memory         int    `json:"memory"`
	Disk           int    `json:"disk"`
	ExtraDisk      int    `json:"extradisk"`
	Uplink         int    `json:"uplink"`
	Traffic        Num    `json:"traffic"` // included traffic in TB
	CPUType        string `json:"cputype"`
	Hostname       string `json:"hostname"`
	StorageType    string `json:"storagetype"`
	DDoSProtection string `json:"ddosprotection"`
	TPM            Flag   `json:"tpm"`
	UEFI           Flag   `json:"uefi"`
}

type ServiceIPs struct {
	IPv4 []struct {
		IP         string `json:"ip"`
		GW         string `json:"gw"`
		Netmask    string `json:"netmask"`
		RDNS       string `json:"rdns"`
		Note       string `json:"note"`
		ProtStatus string `json:"protstatus"` // dynamic | permanent | active | ""
	} `json:"ipv4"`
	IPv6 []struct {
		FirstIP string `json:"firstip"`
		GW      string `json:"gw"`
		Subnet  string `json:"subnet"`
		Netmask string `json:"netmask"`
	} `json:"ipv6"`
	IPv6RDNS []struct {
		IP   string `json:"ip"`
		RDNS string `json:"rdns"`
		Note string `json:"note"`
	} `json:"ipv6adresslist"`
}

type TrafficHistory struct {
	Max              Num     `json:"max"`
	Current          Num     `json:"current"`
	NormalPercentage float64 `json:"normalpercentage"`
	History          struct {
		Last30Days []TrafficPoint `json:"last30days"`
		Months     []TrafficPoint `json:"months"`
	} `json:"history"`
}

type TrafficPoint struct {
	Date string `json:"date"`
	In   Num    `json:"in"`  // MB
	Out  Num    `json:"out"` // MB
	// bar heights in % of the series maximum, computed server-side for the chart
	InPct, OutPct int
}

type Backup struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayname"`
	BackupName  string `json:"backupname"`
	CreatedOn   string `json:"created_on"`
	Locked      Flag   `json:"locked"`
}

type CronJob struct {
	ID          Str    `json:"id"`
	DisplayName string `json:"displayname"`
	Action      string `json:"action"`
	Expression  string `json:"expression"`
	NextExecute string `json:"nextexecute"`
	NotifyDone  Flag   `json:"emailnotifyonfinish"`
	NotifyFail  Flag   `json:"emailnotifyonfailure"`
}

type IncidentsPage struct {
	Data []struct {
		IP        string `json:"ip"`
		Method    string `json:"method"`
		CreatedOn int64  `json:"created_on"`
	} `json:"data"`
	PageInfo struct {
		Last     int `json:"last"`
		StepSize int `json:"stepsize"`
		Total    int `json:"total"`
	} `json:"pageInfo"`
}

type CustomISO struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Status     Num    `json:"status"` // 0 downloading, 1 ready, 2 failed, 3 mounted
	Percentage Str    `json:"percentage"`
}

type OSEntry struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayname"`
}

type ActionLog struct {
	Log  string `json:"log"`
	Time string `json:"time"`
}

type LiveData struct {
	CPU float64 `json:"cpu"`
	Mem int64   `json:"mem"`
	// netin/netout are cumulative Proxmox byte counters, not rates —
	// the client computes MB/s from deltas between polls.
	NetIn  int64 `json:"netin"`
	NetOut int64 `json:"netout"`
	// only present on some hosts (official panel gets it via websocket);
	// nil when the REST endpoint omits it, JSON-encodes as null.
	NodeCPU *float64 `json:"nodecpu"`
}

// AccessPerm is one grantable permission from /user/access/info,
// keyed there by product id; Sub entries require their parent.
type AccessPerm struct {
	Name   string       `json:"name"`
	Header string       `json:"header"`
	Sub    []AccessPerm `json:"sub"`
}

// AccessEntry is one row of /access/list (granted) or /access/list/request
// (invitations to me). created_on is a date string in the first list and a
// unix timestamp in the second — Str swallows both.
type AccessEntry struct {
	ID        string `json:"id"`
	ServiceID string `json:"serviceid"`
	Status    Num    `json:"status"` // 1 pending, 2 active, 3 denied
	CreatedOn Str    `json:"created_on"`
	Name      string `json:"name"`
	ProductID Num    `json:"productid"`
	Entrys    []struct {
		Perm string `json:"perm"`
	} `json:"entrys"`
}

type EmailLogEntry struct {
	ID        string `json:"id"`
	Header    string `json:"header"`
	Template  string `json:"template"`
	CreatedOn int64  `json:"created_on"`
}

// ServiceAddon is an addon already on the service; AddonOffer is orderable.
type ServiceAddon struct {
	ID        Str    `json:"id"`
	Name      string `json:"name"`
	Price     Num    `json:"price"`
	Deletable Flag   `json:"deletable"`
}

type AddonOffer struct {
	Type  Str    `json:"type"`
	Name  string `json:"name"`
	Price Num    `json:"price"`
	Once  Flag   `json:"once"` // one-time purchase, not added to the monthly price
}

type Dashboard struct {
	Credit        Num    `json:"credit"`
	SupportPin    string `json:"supportpin"`
	OrderCount    int    `json:"orderCount"`
	ProductCount  int    `json:"productCount"`
	InvoiceData   Flag   `json:"invoiceData"`
	EmailVerified Num    `json:"emailverified"` // 0=unverified, 1=verified, 2=throwaway address
	Activity      []struct {
		Text string `json:"text"`
		Time string `json:"time"`
	} `json:"activity"`
}

type Invoice struct {
	ID            string `json:"id"` // Sevdesk invoice id — used for the PDF download
	InvoiceNumber string `json:"invoiceNumber"`
	Create        string `json:"create"`
	Sum           Num    `json:"sum"`
	Status        int    `json:"status"`
}

// OrdersPage — the official panel's JS shows /user/{id}/orders returns
// {data, pageInfo}, not the flat array the spec example suggests.
type OrdersPage struct {
	Data     []Order `json:"data"`
	PageInfo struct {
		Last     int `json:"last"`
		StepSize int `json:"stepsize"`
		Total    int `json:"total"`
	} `json:"pageInfo"`
}

type Order struct {
	ID               Num    `json:"id"`
	Status           Num    `json:"status"`
	Type             string `json:"type"`
	OrderInfo        string `json:"orderInfo"`
	DisplayForClient string `json:"displayforclient"`
	CreatedOn        int64  `json:"created_on"`
}

type CreditLogEntry struct {
	Change    Num    `json:"change"`
	Type      string `json:"type"`
	Display   string `json:"display"`
	CreatedOn int64  `json:"created_on"`
}

type DonationInfo struct {
	LinkCount  Num `json:"linkcount"`
	TotalMoney Num `json:"totalmoney"`
}

type DonationLink struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedOn int64  `json:"created_on"`
}

type Donation struct {
	Link      string `json:"link"` // donation link name
	Reason    string `json:"reason"`
	Amount    Num    `json:"amount"`
	CreatedOn int64  `json:"created_on"`
}

type AffiliateInfo struct {
	LinkCount  Num `json:"linkcount"`
	TotalMoney Num `json:"totalmoney"`
	MoneyHold  Num `json:"moneyhold"`
}

type AffiliateLink struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	ServiceCount   Num    `json:"servicecount"`
	ServiceRevenue Num    `json:"servicerevenue"` // arrives as "12.34" string
}

type AffiliateTransaction struct {
	Link      string `json:"link"` // affiliate link name
	Amount    Num    `json:"amount"`
	Status    Num    `json:"status"` // 0 = not paid out yet, 1 = paid out
	CreatedOn int64  `json:"created_on"`
}

type PayByInvoiceInfo struct {
	Limit  Num `json:"limit"`
	Used   Num `json:"used"`
	Status Num `json:"status"` // 1 = pay-by-invoice active
}

type UnpaidEntry struct {
	ID                 Str    `json:"id"`
	Change             Num    `json:"change"`
	Type               string `json:"type"`
	Display            string `json:"display"`
	AdditionalData     string `json:"additionalData"`
	Invoice            Str    `json:"invoice"` // invoice UUID or the literal "default"
	InvoiceDisplayName string `json:"invoicedisplayname"`
	CreatedOn          int64  `json:"created_on"`
}

type OwnInvoice struct {
	ID    string `json:"id"` // UUID, or "default" for the synthetic open-positions entry
	Name  string `json:"name"`
	Total Num    `json:"total"`
}

type PaymentMethodOption struct {
	Method  string `json:"method"`
	Display string `json:"display"`
}

// CatalogPacket — rows from /reseller/packet/list. The same field can be an
// int on one packet variant and a string on another, hence the tolerant types.
type CatalogPacket struct {
	Type        string `json:"type"` // kvmpackage | nextcloudpackage | dedicatedpackage | objectstoragepackage
	ID          string `json:"id"`
	DisplayName string `json:"displayname"`
	Line        string `json:"line"`
	Price       Num    `json:"price"`
	Cores       Str    `json:"cores"`
	Memory      Num    `json:"memory"`
	Disk        Num    `json:"disk"`
	Traffic     Num    `json:"traffic"`
	Active      Num    `json:"active"`
}

type KVMPacket struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayname"`
	Line        string `json:"line"`
	Cores       int    `json:"cores"`
	Memory      int    `json:"memory"`
	Disk        int    `json:"disk"`
	IPv4        int    `json:"ipv4"`
	Price       Num    `json:"price"`
}

type SSHKey struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayname"`
	Key         string `json:"key"`
	CreatedOn   string `json:"created_on"`
}

type InvoiceData struct {
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Company   string `json:"company"`
	Street    string `json:"street"`
	Zip       string `json:"zip"`
	City      string `json:"city"`
	Country   Str    `json:"country"`
}

type UserCountry struct {
	ID          Str    `json:"id"`
	DisplayName string `json:"displayname"`
	VatAmount   Num    `json:"vatamount"`
	Ewr         Num    `json:"ewr"` // 1 = EEA country (affects the credit refund wording)
}

type APISession struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	ExpireAt  string `json:"expire_at"`
	CreatedOn string `json:"created_on"`
}

type TwoFAInit struct {
	QRCode      string   `json:"qrcode"`
	Secret      string   `json:"secret"`
	BackupCodes []string `json:"backupcodes"`
}

// Ticket comes from GET /support/ticket/list — present in the official panel's
// JS but absent from the OpenAPI spec, so fields follow the panel's usage.
type Ticket struct {
	ID         Num    `json:"id"`
	Title      string `json:"title"`
	LastUpdate int64  `json:"last_update"`
	CreatedOn  int64  `json:"created_on"`
	Status     struct {
		Text    string `json:"text"`
		BGColor string `json:"bgcolor"`
	} `json:"status"`
}

// TicketDetail mirrors the reseller ticket-details shape on the undocumented
// customer endpoint GET /support/ticket/{id}.
type TicketDetail struct {
	Title  string `json:"title"`
	Status struct {
		Text    string `json:"text"`
		BGColor string `json:"bgcolor"`
	} `json:"status"`
	Answers []struct {
		Content   string `json:"content"` // the API replaces \n with <br>
		CreatedOn int64  `json:"created_on"`
		Admin     Flag   `json:"admin"`
		Internal  Flag   `json:"internal"`
		Author    struct {
			Username string `json:"username"`
		} `json:"author"`
	} `json:"answers"`
}

type NotificationSetting struct {
	Type        string `json:"type"`
	DisplayName string `json:"displayname"`
	Email       Flag   `json:"email"`
	Discord     string `json:"discord"`
	Webhook     string `json:"webhook"`
}
