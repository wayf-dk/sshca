package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type (
	appHandler func(http.ResponseWriter, *http.Request) error

	Provisioner struct {
		ConfigurationEndpoint string `json:"configurationEndpoint"`
	}

	Opconfig struct {
		Userinfo             string `json:"userinfo_endpoint"`
		Device_authorization string `json:"device_authorization_endpoint"`
		Token                string `json:"token_endpoint"`
	}

	Settings struct {
		Ttl int64
	}

	CaConfig struct {
		Fake, Hide                              bool
		Id, Name, PublicKey                     string
		ClientID, ConfigEndpoint, SSHTemplate   string
		Settings                                Settings
		DefaultPrincipals, AuthnContextClassRef []string
		HashedPrincipal                         bool
		MyAccessID                              bool
		Op                                      Opconfig   `json:"-"`
		Signer                                  ssh.Signer `json:"-"`
	}

	Conf struct {
		RelayingParty             string
		WWW                       embed.FS
		Template                  string
		Verification_uri_template string
		SSOTTL, RendevouzTTL      string
		SshPort                   string
		SshListenOn               string
		WebListenOn               string
		Principal                 string
		AuthnContextClassRef      string
		Assurance                 string
		CaConfigs                 map[string]CaConfig
		Cryptokilib               string
		Slot                      string
		NoOfSessions              int
	}

	idprec struct {
		EntityID     string
		DisplayNames map[string]string
	}
)

const (
	sseRetry = 2000
)

var (
	allowedKeyTypes = map[string]bool{
		"ssh-ed25519":                      true,
		"ssh-ed25519-cert-v01@openssh.com": true,
	}
	Config  Conf
	tmpl    *template.Template
	claims  = &rendezvous{}
	client  = &http.Client{Timeout: 2 * time.Second}
	funcMap = template.FuncMap{
		"PathEscape": url.PathEscape,
	}

	errWait    = errors.New("wait")
	errTimeout = errors.New("timeout")
	ssoTTL, rendevouzTTL time.Duration
)

func Sshca() {
	tmpl = template.Must(template.New("ca.template").Funcs(funcMap).Parse(Config.Template))
	claims.ttl = Config.RendevousTTL * time.Second
	Config.SshPort = Config.SshListenOn[strings.Index(Config.SshListenOn, ":")+1:]
	ssoTTL, _ = time.ParseDuration(Config.SSOTTL)
	rendevouzTTL, _ = time.ParseDuration(Config.RendevouzTTL)
	claims.ttl = ssoTTL
	claims.cleanUp()
	Config.SshPort = Config.SshListenOn[strings.Index(Config.SshListenOn, ":")+1:]
	prepareCAs()
	go sshserver()

	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.Handle("/", appHandler(sshcaRouter))

	fmt.Println("Listening on port: " + Config.WebListenOn)
	err := http.ListenAndServe(Config.WebListenOn, nil)
	fmt.Println("err: ", err)
}

func sshcaRouter(w http.ResponseWriter, r *http.Request) (err error) {
	path := strings.Split(r.URL.Path+"//", "/")
	p := path[1]
	switch p { // handle /www /feedback /sso
	case "www":
		http.ServeFileFS(w, r, Config.WWW, r.URL.Path)
		return
	case "feedback":
		return feedbackHandler(w, r)
	case "sso": // returning from login
		return ssoHandler(w, r)
	default:
		ca, ok := Config.CaConfigs[p]
		if ok { // handle /<ca>/.*
			p2 := path[2]
			switch p2 {
			case "config":
				jsonTxt, _ := json.MarshalIndent(ca, "", "    ")
				w.Header().Add("Content-Type", "application/json")
				w.Write(jsonTxt)
				return
			case "sign":
				return sshsignHandler(w, r)
			case "mindthegap":
				return mindthegap(w, r, ca)
			case "ri":
				return riHandler(w, r, ca)
			default:
    			if err = mindthegapPassive(w, r, ca); err != nil {
    			    return
    			}
				err = tmpl.ExecuteTemplate(w, "login", map[string]any{"ca": ca})
				return
			}
		}
		err = tmpl.ExecuteTemplate(w, "listCAs", map[string]any{"config": Config.CaConfigs})
		return
	}
}

func prepareCAs() {
	for i, v := range Config.CaConfigs {
		if v.ConfigEndpoint != "" {
			v.Op = Opconfig{}
			resp, _ := http.Get(v.ConfigEndpoint)
			configJson, _ := io.ReadAll(resp.Body)
			json.Unmarshal(configJson, &v.Op)
		}
		if v.Signer == nil {
			pubkey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(v.PublicKey))
			privkeyLabel := base64.RawURLEncoding.EncodeToString(pubkey.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)[:])
			if priv, ok := findPrivatekey(privkeyLabel); ok {
				v.Signer = hsmSigner{
					priv: priv,
					pub:  pubkey,
				}
			}
		}
		v.Id = i
		Config.CaConfigs[i] = v
	}

	if Config.CaConfigs["transport"].Signer == nil {
		log.Panic("Transport signer is nil")
	}
}

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteAddr := r.RemoteAddr
	if ra, ok := r.Header["X-Forwarded-For"]; ok {
		remoteAddr = ra[0]
	}

	// log.Printf("%s %s %s %+v", remoteAddr, r.Method, r.Host, r.URL)
	starttime := time.Now()

	w.Header().Set("X-Frame-Options", "sameorigin")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
	w.Header().Set("X-XSS-Protection", "0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

	err := fn(w, r)

	status := 200
	if err != nil {
		status = 500
		if err.Error() == "401" {
			status = 401
		}
		http.Error(w, err.Error(), status)
	} else {
		err = fmt.Errorf("OK")
	}

	//log.Printf("%s: %s", err, r.Header.Get("User-Agent"))
	log.Printf("%s %s %s %+v %1.3f %d %s", remoteAddr, r.Method, r.Host, r.URL, time.Since(starttime).Seconds(), status, err)
}

func riHandler(w http.ResponseWriter, r *http.Request, ca CaConfig) (err error) {
	r.ParseForm()
	if ca.ClientID != "" {
		err = deviceflowHandler(w, ca)
		return
	}
	token := claims.set("", certInfo{ca: ca.Id})
	data := url.Values{}
	data.Set("state", token)
	data.Set("idpentityid", r.Form.Get("entityID"))
	if len(ca.AuthnContextClassRef) > 0 {
		data.Set("acr_values", strings.Join(ca.AuthnContextClassRef, " "))
	}
	http.Redirect(w, r, "/sso?"+data.Encode(), http.StatusFound)
	return
}

func ssoHandler(w http.ResponseWriter, r *http.Request) (err error) {
	r.ParseForm()
	token := r.Form.Get("state")
	if ci, ok := claims.get(token); ok { // see if it is a token
		ci.principal = r.Header.Get(Config.Principal)
		ca := Config.CaConfigs[ci.ca]
		if ca.Fake {
			ci.principal = "a_really_fake_principal"
		}
		if ci.principal != "" {
			wantedAcrs := ca.AuthnContextClassRef
			acrs := strings.Split(r.Header.Get(Config.AuthnContextClassRef), ",")
			acrs = append(acrs, strings.Split(r.Header.Get(Config.Assurance), ",")...)
			if len(wantedAcrs) > 0 && intersectionEmpty(wantedAcrs, acrs) {
				return fmt.Errorf("no valid AuthnContextClassRef found: %v vs. %v", wantedAcrs, acrs)
			}
			ci.username = usernameFromPrincipal(ci.principal, ca)
			ci.eol = time.Now().Add(rendevouzTTL)
			claims.set(token, ci)
			err = tmpl.ExecuteTemplate(w, "login", map[string]any{"ci": ci, "ca": ca, "token": token, "sshport": Config.SshPort})
		}
	}
	return
}

func feedbackHandler(w http.ResponseWriter, r *http.Request) (err error) {
	path := strings.Split(r.URL.Path+"//", "/")
	token := path[2]
	ci, ok := claims.get(token)
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")

	if ok && ci.cert != nil {
		fmt.Fprintf(w, "event: certready\n%s\n\n", certPP(ci.cert, "data: "))
		return nil
	}
	if ok && ci.principal != "" {
		fmt.Fprintf(w, "event: cmdready\ndata: %s\nretry: %d\n\n", ci.username, sseRetry)
		return nil
	}
	if ok {
		fmt.Fprintf(w, "data: wait\nretry: %d\n\n", sseRetry)
		return nil
	}
	fmt.Fprintf(w, "event: timeout\ndata: %s\n\n", "timeout")
	return nil
}

func sshsignHandler(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	r.ParseForm()
	path := strings.Split(r.URL.Path, "/")
	ca := path[1]
	config, ok := Config.CaConfigs[ca]
	if !ok {
		return fmt.Errorf("CA not found: %s", ca)
	}
	params := map[string]string{}
	req, _ := io.ReadAll(r.Body)
	err = json.Unmarshal(req, &params)
	if err != nil {
		return
	}
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(params["PublicKey"]))
	if err != nil {
		return
	}
	resp, err := getUserinfo(params["OTT"], config.Op.Userinfo)
	if err != nil {
		return
	}

	val, ok := resp["sub"].(string)
	if !ok {
		return fmt.Errorf("sub not found: %s", ca)
	}

	ci := certInfo{principal: val, username: usernameFromPrincipal(val, config)}

	sshCertificate, err := newCertificate(config, publicKey, ci)
	if err != nil {
		return
	}
	res := ssh.MarshalAuthorizedKey(sshCertificate)
	w.Write(res)
	return
}

func mindthegapCheckIDPName(w http.ResponseWriter, r *http.Request, ca string) (entityIDJSON string, err error) {
	r.ParseForm()
	cookieName := "mtg-" + ca
	if _, ok := r.Form["entityID"]; ok {
		entityIDJSON = r.Form.Get("entityIDJSON")
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: base64.URLEncoding.EncodeToString([]byte(entityIDJSON)), Path: "/", Secure: true, HttpOnly: true, MaxAge: 34560000})
		return
	}
	if tmp, err := r.Cookie(cookieName); err == nil {
		if data, err := base64.StdEncoding.DecodeString(tmp.Value); err == nil {
			entityIDJSON = string(data)
			return entityIDJSON, err
		}
	}
	return "", wasPassive
}

func mindthegapPassive(w http.ResponseWriter, r *http.Request, ca CaConfig) (err error) {
    if ca.ClientID != "" {
        return
    }
	if _, err = mindthegapCheckIDPName(w, r, ca.Id); err == nil {
		return
	}
	discoURL := "https://wayf.wayf.dk/ds/?"
	dsParams := url.Values{}
	dsParams.Set("return", "https://"+r.Host+"/"+ca.Id)
	dsParams.Set("entityID", Config.RelayingParty)
	dsParams.Set("policy", "mindthegap,v2")
	dsParams.Set("isPassive", "true")
	dsParams.Set("return", "https://"+r.Host+"/"+ca.Id)
	http.Redirect(w, r, discoURL+dsParams.Encode(), http.StatusFound)
	return wasPassive
}

func mindthegap(w http.ResponseWriter, r *http.Request, ca CaConfig) (err error) {
	if ca.ClientID != "" {
		idpName = ca.Name
		err = tmpl.ExecuteTemplate(w, "mindthegap", map[string]string{"idpName": idpName, "riURL": riURL})
		return
	}
	entityIDJSON, _ := mindthegapCheckIDPName(w, r, ca.Id)
	caURL := "https://" + r.Host + "/" + ca.Id
	riURL := caURL + "/ri"
	discoURL := "https://wayf.wayf.dk/ds/?"
	idpName := "Access through your Institution"
	dsParams := url.Values{}
	dsParams.Set("return", caURL+"/mindthegap")
	dsParams.Set("entityID", Config.RelayingParty)
	dsParams.Set("policy", "mindthegap,v2")
	idp := idprec{}
	errr := json.Unmarshal([]byte(entityIDJSON), &idp)
	if errr == nil && idp.EntityID != "" {
		idpName = idp.DisplayNames["en"]
		riURL += "?entityID=" + url.QueryEscape(idp.EntityID)
		if _, ok := r.Form["entityID"]; ok {
			http.Redirect(w, r, riURL, http.StatusFound)
			return
		}
	} else {
		riURL = discoURL + dsParams.Encode()
	}
	dsParams.Set("policy", "v2")
	p := map[string]string{"idpName": idpName, "riURL": riURL, "discoURL": discoURL + dsParams.Encode()}
	err = tmpl.ExecuteTemplate(w, "mindthegap", p)
	return
}

func sshserver() {
	sshConfig := &ssh.ServerConfig{
		// Remove to disable public key auth.
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if !allowedKeyTypes[pubKey.Type()] {
				return nil, errors.New("xxx")
			}
			permissions := &ssh.Permissions{
				Extensions: map[string]string{
					"pubkey": string(pubKey.Marshal()),
					"user":   c.User(),
				},
			}
			if c.User() == "demo" {
				if _, ok := pubKey.(*ssh.Certificate); !ok {
					return nil, errors.New("xxx")
				}
			}
			return permissions, nil
		},
	}

	sshConfig.AddHostKey(Config.CaConfigs["transport"].Signer)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", Config.SshListenOn)
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	fmt.Println("listening on " + Config.SshListenOn)

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Println("failed to accept incoming connection: ", err)
			continue
		}
		go handleSSHConnection(nConn, sshConfig)
	}
}

func handleSSHConnection(nConn net.Conn, sshConfig *ssh.ServerConfig) {
	type tokenType uint8
	const (
		normal tokenType = iota
		device
	)

	conn, chans, reqs, err := ssh.NewServerConn(nConn, sshConfig)
	if err != nil {
		log.Println("failed to handshake: ", err)
		return
	}

	xtras := conn.Permissions.Extensions
	publicKey, _ := ssh.ParsePublicKey([]byte(xtras["pubkey"]))
	user := xtras["user"]

	// The incoming Request channel must be serviced.
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			return
		}

		channel, reqs, err := newChannel.Accept()
		if err != nil {
			log.Println("Could not accept channel", err)
		}

		for req := range reqs {
			switch req.Type {
			case "exec":
				args := strings.Split(string(req.Payload[4:])+"  ", " ") // always at least 2 elements
				cmd, token := args[0], args[1]
				switch cmd {
				case "token":
					ci, ok := claims.get(token)
					if ok && user != "" && ci.cert == nil {
						cert, err := newCertificate(Config.CaConfigs[ci.ca], publicKey, ci)
						if err == nil {
							certTxt := ssh.MarshalAuthorizedKey(cert)
							fmt.Fprintf(channel, "%s", certTxt)
							ci.cert = cert
							claims.set(token, ci)
						}
					}
				case "demo":
					demoCert(channel, publicKey)
				}
				channel.Close()
			case "shell":
				channel.Close()
			}
		}
	}
	conn.Close()
}

func demoCert(channel ssh.Channel, publicKey ssh.PublicKey) {
	if cert, ok := publicKey.(*ssh.Certificate); ok {
		channel.Write(certPP(cert, ""))
		io.WriteString(channel, "\n")
		signatureKey := strings.TrimRight(string(ssh.MarshalAuthorizedKey(cert.SignatureKey)), "\n")
		signedByUs := false
		ca := ""
		for i, v := range Config.CaConfigs {
			if v.Signer == nil {
				continue
			}
			if signedByUs = signatureKey == v.PublicKey; signedByUs {
				ca = i
				break
			}
		}
		if !signedByUs {
			fmt.Fprintln(channel, "Certificate is not signed by this service")
		} else {
			fmt.Fprintf(channel, `Certificate is signed by the "%s" CA%s`, ca, "\n")
		}

		// from ssh.certs.go CheckCert
		unixNow := time.Now().Unix()
		if after := int64(cert.ValidAfter); after < 0 || unixNow < int64(cert.ValidAfter) {
			fmt.Fprintln(channel, `Certificate is not yet valid`)
		}
		if before := int64(cert.ValidBefore); cert.ValidBefore != uint64(ssh.CertTimeInfinity) && (unixNow >= before || before < 0) {
			fmt.Fprintln(channel, `Certificate has expired`)
		}
		// from ssh.certs.go - bytesForSigning
		c2 := *cert
		c2.Signature = nil
		out := c2.Marshal()
		// Drop trailing signature length.
		bytesForSigning := out[:len(out)-4]

		if err := cert.SignatureKey.Verify(bytesForSigning, cert.Signature); err != nil {
			fmt.Fprintln(channel, "Certificate signature does not verify")
		}
	}
}

func newCertificate(ca CaConfig, pubkey ssh.PublicKey, ci certInfo) (cert *ssh.Certificate, err error) {
	if _, ok := pubkey.(*ssh.Certificate); ok {
		pubkey = pubkey.(*ssh.Certificate).Key
	}

	now := time.Now().In(time.FixedZone("UTC", 0)).Unix()
	principals := []string{ci.principal}
	if ci.username != "" {
		principals = append(principals, ci.username)
	}
	cert = &ssh.Certificate{
		CertType: ssh.UserCert,
		Key:      pubkey,
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{}, // "force-command": "id ; pwd ; /usr/bin/ls -a"},
			Extensions:      map[string]string{"permit-agent-forwarding": "", "permit-pty": ""},
			// Extensions:      map[string]string{"permit-agent-forwarding": "", "permit-pty": "", "groups@wayf.dk": data},
		},
		KeyId:           ci.principal,
		ValidPrincipals: append(ca.DefaultPrincipals, principals...),
		ValidAfter:      uint64(now - 60),
		ValidBefore:     uint64(now + ca.Settings.Ttl),
	}
	err = cert.SignCert(rand.Reader, ca.Signer)
	return
}

func usernameFromPrincipal(principal string, ca CaConfig) (username string) {
	if ca.HashedPrincipal {
		hashed := sha256.Sum256([]byte(principal))
		username = strings.TrimLeft(base64.RawURLEncoding.EncodeToString(hashed[:24]), "-") // - (dash) not allowed as 1st character
		return
	}
	if ca.MyAccessID {
		username = strings.ReplaceAll(principal[:35], "-", "")
		return
	}
	return
}

func certPP(cert *ssh.Certificate, prefix string) (pp []byte) {
	const iso = "2006-01-02T15:04:05"
	va := time.Unix(int64(cert.ValidAfter), 0).Format(iso)
	vb := time.Unix(int64(cert.ValidBefore), 0).Format(iso)
	//hours := rec.cert.ValidBefore - cert.ValidAfter
	pp, _ = json.MarshalIndent(cert, prefix, "    ")
	pp = append([]byte(prefix), pp...) // no prefix on 1st line ???
	pp = regexp.MustCompile(`("ValidAfter": )(\d+),`).ReplaceAll(pp, []byte(`${1}`+va+`,`))
	pp = regexp.MustCompile(`("ValidBefore": )(\d+),`).ReplaceAll(pp, []byte(`${1}`+vb+`,`))
	return pp
}

// nonce
func nonce() (s string) {
	b := make([]byte, 8) // 64 bits
	_, err := rand.Read(b)
	if err != nil {
		log.Panic("Problem with making random number:", err)
	}
	b[0] = b[0] & byte(0x7f) // make sure it is a positive number
	return hex.EncodeToString(b)
}

// PP - super simple Pretty Print - using JSON
func PP(i ...interface{}) {
	for _, e := range i {
		switch v := e.(type) {
		case []byte:
			fmt.Println(string(v))
		default:
			s, _ := json.MarshalIndent(v, "", "    ")
			fmt.Println(string(s))
		}
	}
	return
}

// rendezvous

type (
	certInfo struct {
		ca        string
		principal string
		username  string
		cert      *ssh.Certificate
		eol       time.Time
	}

	rendezvous struct {
		info sync.Map
		ttl  time.Duration
	}
)

func (rv *rendezvous) cleanUp() {
	ticker := time.NewTicker(rv.ttl)
	go func() {
		for {
			<-ticker.C
			rv.info.Range(func(k, v interface{}) bool {
				if v.(certInfo).eol.Before(time.Now()) {
					rv.info.Delete(k)
				}
				return true
			})
		}
	}()
}

func (rv *rendezvous) set(token string, ci certInfo) string {
	if token == "" {
		token = nonce()
	}
	if ci.eol.IsZero() {
		ci.eol = time.Now().Add(rv.ttl)
	}
	rv.info.Store(token, ci)
	return token
}

func (rv *rendezvous) get(token string) (ci certInfo, ok bool) {
	a, ok := rv.info.Load(token)
	if ok {
		ci = a.(certInfo)
		if ci.eol.Before(time.Now()) {
			rv.info.Delete(token)
			return ci, false
		}
	}
	return
}

// ssh-agent

func GetSignerFromSshAgent() (pubkey string, signer ssh.Signer) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatalf("Failed to open SSH_AUTH_SOCK: %v", err)
	}
	agent := agent.NewClient(conn)
	signers, err := agent.Signers()
	if err != nil {
		log.Panicf("Getting signers from ssh-agent failed: %v", err)
	}
	for _, s := range signers {
		if allowedKeyTypes[s.PublicKey().Type()] {
			pubkey = strings.TrimRight(string(ssh.MarshalAuthorizedKey(s.PublicKey())), "\n")
			signer = s
			return
		}
	}
	log.Fatalln("No ed25519 keys available in ssh-agent")
	return
}

func intersectionEmpty(s1, s2 []string) (res bool) {
	hash := make(map[string]bool)
	for _, e := range s1 {
		hash[e] = true
	}
	for _, e := range s2 {
		if hash[e] {
			return false
		}
	}
	return true
}
