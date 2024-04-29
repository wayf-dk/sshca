package sshca

import (
    "cmp"
	"crypto/ed25519"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
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

	sessionInfo struct {
		user      string
		publicKey ssh.PublicKey
	}

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
	    Fake                     bool
		Id, Name, PublicKey     string
		ClientID, ConfigEndpoint string
		Settings                 Settings
		Op                       Opconfig   `json:"-"`
		Signer                   ssh.Signer `json:"-"`
	}

	Conf struct {
		WWW                       embed.FS
		Template                  string
		Verification_uri_template string
		RendevouzTTL              time.Duration
		SshPort                   string
		SshListenOn               string
		WebListenOn               string
		Principal                 string
		CaConfigs                 map[string]CaConfig
		Cryptokilib               string
		Slot                      string
		NoOfSessions              int
	}
)

var (
	allowedKeyTypes = map[string]bool{
		"ssh-ed25519":                      true,
		"ssh-ed25519-cert-v01@openssh.com": true,
	}
	Config     Conf
	tmpl       *template.Template
	claims     = &rendezvous{info: map[string]certInfo{}}
	publicKeys = &publicKeyMap{info: map[string]sessionInfo{}}
	client     = &http.Client{Timeout: 2 * time.Second}
)

func Sshca() {
	tmpl = template.Must(template.New("ca.template").Parse(Config.Template))
	claims.ttl = Config.RendevouzTTL * time.Second
	Config.SshPort = Config.SshListenOn[strings.Index(Config.SshListenOn, ":")+1:]
	claims.cleanUp()
	prepareCAs()
	go sshserver()

	/*
	   /
	   /<ca>
	   /<ca>/www/<what>
	   /<ca>/<path>
	   /<token>
	   /www/...
	   /feedback/<token>
	   /sso
	*/

	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.Handle("/", appHandler(sshcaRouter))

	fmt.Println("Listening on port: " + Config.WebListenOn)
	err := http.ListenAndServe(Config.WebListenOn, nil)
	fmt.Println("err: ", err)
}

func sshcaRouter(w http.ResponseWriter, r *http.Request) (err error) {
	r.ParseForm()
	path := strings.Split(r.URL.Path+"//", "/")
	p := path[1]
	switch p { // handle /www /feedback /sso and /<token>
	case "www":
		http.ServeFileFS(w, r, Config.WWW, r.URL.Path)
		return
	case "feedback":
		return feedbackHandler(w, r)
	case "sso": // returning from login
		return ssoHandler(w, r)
	default:
		p2 := path[2]
	    var token string
	    var ci certInfo
	    var tkOK bool
	    config, caOK := Config.CaConfigs[p]
	    if !caOK {
	        config, caOK = Config.CaConfigs[p2]
	        ci, token, tkOK = claims.get(p)
	    }
	    if !tkOK {
	        ci, token, tkOK = claims.get(p2)
	    }
	    if !caOK && tkOK {
	        config, caOK = Config.CaConfigs[ci.ca]
	    }
        if token == "" {
            token = claims.put(ci) //
        }

        if caOK { // handle /<ca>/.*
            switch p2 {
            case "config":
                jsonTxt, _ := json.MarshalIndent(config, "", "    ")
                w.Header().Add("Content-Type", "application/json")
                w.Write(jsonTxt)
                return
            case "sign":
                return sshsignHandler(w, r)
            default: // we assume we have a valid token
            }
            ci.ca = config.Id
            claims.upd(token, ci)
			return tokenHandler(w, r, token, ci, config)
        }
        err = tmpl.ExecuteTemplate(w, "listCAs", map[string]any{"config": Config.CaConfigs, "token": token} )
        return
	}
	return
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
			v.Signer = hsmSigner{
				priv: findPrivatekey(privkeyLabel),
				pub:  pubkey,
			}
		}
	    v.Id = i
		Config.CaConfigs[i] = v
	}
	// PP(Config)
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

func ssoHandler(w http.ResponseWriter, r *http.Request) (err error) {
    r.ParseForm()
    token := r.Form.Get("state") // when returning
    if ci, _, ok := claims.get(token); ok {   // see if it is a token
        principal := r.Header.Get(Config.Principal)
        if Config.CaConfigs[ci.ca].Fake {
            principal = "a_really_fake_principal"
        }
        if principal != "" {
            attrs := map[string]any{"eduPersonPrincipalName": principal}
            claims.meet(token, certInfo{claims: attrs})
            claims.set(token+"_feedback", certInfo{})
            err = tmpl.ExecuteTemplate(w, "login", map[string]any{"ca": ci.ca, "state": token, "sshport": Config.SshPort})
        }
    }
    return
}

func tokenHandler(w http.ResponseWriter, r *http.Request, token string, ci certInfo, config CaConfig ) (err error) {
	r.ParseForm()
    ca, idp := config.Id, cmp.Or(ci.idp, r.Form.Get("idpentityid"))
    if config.ClientID != "" {
        err = deviceflowHandler(w, config, token)
        return
    } else if idp == "" {
        err = tmpl.ExecuteTemplate(w, "login", map[string]string{"token": token, "ca": ca, "sshport": Config.SshPort})
        return
    } else {
        if config.Fake {
            return
        }
        data := url.Values{}
        data.Set("state", token)
        data.Set("idpentityid", idp)
        http.Redirect(w, r, "/sso?"+data.Encode(), http.StatusFound)
        return
    }
	return
}

func feedbackHandler(w http.ResponseWriter, r *http.Request) (err error) {
	r.ParseForm()
	path := strings.Split(r.URL.Path, "/")
	token := path[2]
	rec, err := claims.wait(token + "_feedback")
	if err != nil {
		return
	}
	if rec.cert != nil {
		w.Write(certPP(rec.cert))
	}
	return
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
	sshCertificate, err := newCertificate(config, publicKey, resp)
	if err != nil {
		return
	}
	res := ssh.MarshalAuthorizedKey(sshCertificate)
	w.Write(res)
	return
}

func sshserver() {
	sshConfig := &ssh.ServerConfig{
		// Remove to disable public key auth.
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if !allowedKeyTypes[pubKey.Type()] {
				return nil, errors.New("xxx")
			}
			_, ok := pubKey.(*ssh.Certificate)
			if c.User() == "demo" && !ok {
				return nil, errors.New("xxx")
			}
			publicKeys.set(string(c.SessionID()), sessionInfo{c.User(), pubKey})
			return nil, nil // errors.New("xxx")
		},
	}

	if Config.CaConfigs["transport"].Signer == nil {
		log.Panic("Transport signer is nil")
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
				si := publicKeys.get(string(conn.SessionID()))
				args := strings.Split(string(req.Payload[4:])+"  ", " ") // always at least 2 elements
				cmd, token := args[0], args[1]
				f1 := flag.NewFlagSet("", flag.ExitOnError)
                ca := f1.String("ca", "", "")
                idp := f1.String("idp", "", "")
                f1.Parse(args[1:])
				switch cmd {
				case "token":
				case "ca":
					token = claims.put(certInfo{ca: *ca, idp: *idp})
					io.WriteString(channel, fmt.Sprintf(Config.Verification_uri_template, token))
				case "demo":
					if cert, ok := si.publicKey.(*ssh.Certificate); ok {
						channel.Write(certPP(cert))
						io.WriteString(channel, "\n")
					}
					channel.Close()
					return
				default:
					req.Reply(true, nil)
					continue
				}
				xtra, err := claims.wait(token)
				if si.user != "" && err == nil {
					cert, err := newCertificate(Config.CaConfigs[xtra.ca], si.publicKey, xtra.claims)
					if err == nil {
						certTxt := ssh.MarshalAuthorizedKey(cert)
						// keyName := si.publicKey.Type()[4:]
						io.WriteString(channel, fmt.Sprintf("%s\n", certTxt)) //, keyName)) // certTxt already have a linefeed at the end ..
					}
					claims.meet(token+"_feedback", certInfo{cert: cert, err: err})
				}
				channel.Close()
			}
			req.Reply(true, nil)
		}
		channel.Close()
	}
	conn.Close()
}

func newCertificate(ca CaConfig, pubkey ssh.PublicKey, claims map[string]any) (cert *ssh.Certificate, err error) {
	if _, ok := pubkey.(*ssh.Certificate); ok {
		pubkey = pubkey.(*ssh.Certificate).Key
	}
	var principal string
	if val, ok := claims["eduPersonPrincipalName"].(string); ok {
		principal = val
	} else if val, ok := claims["sub"].(string); ok {
		principal = val
	} else {
		return nil, errors.New("no principal found")
	}
	now := time.Now().In(time.FixedZone("UTC", 0)).Unix()
	cert = &ssh.Certificate{
		CertType: ssh.UserCert,
		Key:      pubkey,
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{}, // "force-command": "id ; pwd ; /usr/bin/ls -a"},
			Extensions:      map[string]string{"permit-agent-forwarding": "", "permit-pty": ""},
			// Extensions:      map[string]string{"permit-agent-forwarding": "", "permit-pty": "", "groups@wayf.dk": data},
		},
		KeyId:           principal,
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(now - 60),
		ValidBefore:     uint64(now + ca.Settings.Ttl),
	}
	err = cert.SignCert(rand.Reader, ca.Signer)
	return
}

func certPP(cert *ssh.Certificate) ([]byte) {
    const iso = "2006-01-02T15:04:05"
    va := time.Unix(int64(cert.ValidAfter), 0).Format(iso)
    vb := time.Unix(int64(cert.ValidBefore), 0).Format(iso)
    //hours := rec.cert.ValidBefore - cert.ValidAfter
    pp, _ := json.MarshalIndent(cert, "", "    ")
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
	b[0] = b[0] & byte(0x7f) // make sure it is a positive 64 bit number
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
		ch      chan bool
		created time.Time
		ca, idp string
		claims  map[string]any
		cert    *ssh.Certificate
		err     error
	}

	rendezvous struct {
		mx   sync.RWMutex
		info map[string]certInfo
		ttl  time.Duration
	}
)

func (rv *rendezvous) cleanUp() {
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for {
			<-ticker.C
			rv.mx.Lock()
			toOld := time.Now().Add(-rv.ttl)
			for k, v := range rv.info {
				if v.created.Before(toOld) {
					delete(rv.info, k)
				}
			}
			rv.mx.Unlock()
		}
	}()
}

func (rv *rendezvous) upd(token string, xtra certInfo) {
	rv.mx.Lock()
	defer rv.mx.Unlock()
    old, _ := rv.info[token]
    xtra.ch = old.ch
    xtra.created = old.created
    rv.info[token] = xtra
    return
}

func (rv *rendezvous) set(token string, xtra certInfo) {
	rv.mx.Lock()
	defer rv.mx.Unlock()
	xtra.ch = make(chan bool, 1)
	xtra.created = time.Now()
	rv.info[token] = xtra
	return
}

func (rv *rendezvous) put(xtra certInfo) (token string) {
	token = nonce()
	rv.set(token, xtra)
	return
}

func (rv *rendezvous) get(token string) (xtra certInfo, tk string, ok bool) {
	rv.mx.RLock()
	defer rv.mx.RUnlock()
	xtra, ok = rv.info[token]
	if ok {
    	tk = token
    }
	return
}

func (rv *rendezvous) meet(token string, info certInfo) {
	rv.mx.Lock()
	defer rv.mx.Unlock()
	xtra, ok := rv.info[token]
	if ok {
		xtra.ch <- true
		xtra.claims = info.claims
		xtra.cert = info.cert
		xtra.err = info.err
		rv.info[token] = xtra
	}
}

func (rv *rendezvous) wait(token string) (xtra certInfo, err error) {
	rv.mx.RLock()
	xtra, ok := rv.info[token]
	rv.mx.RUnlock()
	if !ok {
		err = errors.New("no userinfo")
		return
	}
	select {
	case <-xtra.ch:
	case <-time.After(rv.ttl):
		err = errors.New("rendevouz timeout")
	}
	rv.mx.Lock()
	defer rv.mx.Unlock()
	xtra, _ = rv.info[token]
	delete(rv.info, token)
	return
}

// pubkeys

type (
	publicKeyMap struct {
		info map[string]sessionInfo
		mx   sync.RWMutex
	}
)

func (pk *publicKeyMap) set(k string, v sessionInfo) {
	pk.mx.Lock()
	defer pk.mx.Unlock()
	pk.info[k] = v
}

func (pk *publicKeyMap) get(k string) (v sessionInfo) {
	pk.mx.Lock()
	defer pk.mx.Unlock()
	v, _ = pk.info[k]
	delete(pk.info, k)
	return
}

// ssh-agent

func GetSignerFromSshAgent() (pubkey string, signer ssh.Signer) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return
		//		log.Fatalf("Failed to open SSH_AUTH_SOCK: %v", err)
	}
	agent := agent.NewClient(conn)
	signers, err := agent.Signers()
	if err != nil {
		log.Panicf("RequestIdentities: %v", err)
	}
	for _, s := range signers {
		if allowedKeyTypes[s.PublicKey().Type()] {
			pubkey = string(ssh.MarshalAuthorizedKey(s.PublicKey()))
			signer = s
			return
		}
	}
	return
}
