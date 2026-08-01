package main

// Minimal Datalix API client. Auth is a token query parameter; POST bodies are
// multipart/form-data (per the OpenAPI spec at backend.datalix.de/v1).

import (
	"bytes"
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

func (a API) get(path string, out any) error    { return a.do(http.MethodGet, path, nil, out) }
func (a API) delete(path string) error          { return a.do(http.MethodDelete, path, nil, nil) }
func (a API) post(path string, form map[string]string) error {
	if form == nil {
		form = map[string]string{}
	}
	return a.do(http.MethodPost, path, form, nil)
}
func (a API) postOut(path string, form map[string]string, out any) error {
	return a.do(http.MethodPost, path, form, out)
}

func (a API) do(method, path string, form map[string]string, out any) error {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	u := apiBase + path + sep + "token=" + url.QueryEscape(a.token)

	var body io.Reader
	contentType := ""
	if form != nil {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for k, v := range form {
			mw.WriteField(k, v)
		}
		mw.Close()
		body = &buf
		contentType = mw.FormDataContentType()
	}

	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := apiHTTP.Do(req)
	if err != nil {
		return errors.New("Datalix API unreachable")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return errors.New("Datalix API read error")
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(data, &e)
		msg := e.Error
		if msg == "" {
			msg = "API error (HTTP " + strconv.Itoa(resp.StatusCode) + ")"
		}
		return &apiError{msg: msg, status: resp.StatusCode}
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return errors.New("unexpected API response")
		}
	}
	return nil
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
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
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
	ID             string `json:"id"`
	DeleteAt       int64  `json:"delete_at"`
	ExpireAt       int64  `json:"expire_at"`
	Name           string `json:"name"`
	Price          Num    `json:"price"`
	ProductDisplay string `json:"productdisplay"`
	IP             string `json:"ip"`
	Domain         string `json:"domain"`
	Fav            Flag   `json:"fav"`
	Locked         Flag   `json:"locked"`
	LockReason     string `json:"lockreason"`
	DeleteDone     Flag   `json:"deletedone"`
}

type ServiceInfo struct {
	Display struct {
		Backup   Flag `json:"backup"`
		Hardware Flag `json:"hardware"`
		IP       Flag `json:"ip"`
		LiveData Flag `json:"livedata"`
		Traffic  Flag `json:"traffic"`
	} `json:"display"`
	Product struct {
		MAC      string `json:"mac"`
		Status   string `json:"status"`
		User     string `json:"user"`
		Password string `json:"password"`
		Hostname string `json:"hostname"`
	} `json:"product"`
	Service Service `json:"service"`
}

type Hardware struct {
	Cores          int    `json:"cores"`
	Memory         int    `json:"memory"`
	Disk           int    `json:"disk"`
	Uplink         int    `json:"uplink"`
	CPUType        string `json:"cputype"`
	Hostname       string `json:"hostname"`
	StorageType    string `json:"storagetype"`
	DDoSProtection string `json:"ddosprotection"`
}

type ServiceIPs struct {
	IPv4 []struct {
		IP      string `json:"ip"`
		GW      string `json:"gw"`
		Netmask string `json:"netmask"`
		RDNS    string `json:"rdns"`
	} `json:"ipv4"`
	IPv6 []struct {
		FirstIP string `json:"firstip"`
		GW      string `json:"gw"`
		Subnet  string `json:"subnet"`
	} `json:"ipv6"`
}

type TrafficHistory struct {
	Max              Num     `json:"max"`
	Current          Num     `json:"current"`
	NormalPercentage float64 `json:"normalpercentage"`
}

type Backup struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayname"`
	BackupName  string `json:"backupname"`
	CreatedOn   string `json:"created_on"`
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
	CPU    float64 `json:"cpu"`
	Mem    int64   `json:"mem"`
	NetIn  int64   `json:"netin"`
	NetOut int64   `json:"netout"`
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
	InvoiceNumber string `json:"invoiceNumber"`
	Create        string `json:"create"`
	Sum           Num    `json:"sum"`
	Status        int    `json:"status"`
}

type Order struct {
	DisplayForClient string `json:"displayforclient"`
	CreatedOn        int64  `json:"created_on"`
	Price            Num    `json:"price"`
	Paid             Flag   `json:"paid"`
}

type CreditLogEntry struct {
	Change    Num    `json:"change"`
	Type      string `json:"type"`
	Display   string `json:"display"`
	CreatedOn int64  `json:"created_on"`
}

type SSHKey struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayname"`
	Key         string `json:"key"`
	CreatedOn   string `json:"created_on"`
}

type InvoiceData struct {
	FirstName          string `json:"firstname"`
	LastName           string `json:"lastname"`
	Company            string `json:"company"`
	Street             string `json:"street"`
	Zip                string `json:"zip"`
	City               string `json:"city"`
	Country            Str    `json:"country"`
}

type UserCountry struct {
	ID          Str    `json:"id"`
	DisplayName string `json:"displayname"`
	VatAmount   Num    `json:"vatamount"`
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

type NotificationSetting struct {
	Type        string `json:"type"`
	DisplayName string `json:"displayname"`
	Email       Flag   `json:"email"`
	Discord     string `json:"discord"`
	Webhook     string `json:"webhook"`
}
