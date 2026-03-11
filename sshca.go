package sshca

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/oauth2"
)

type (
	Flow   int
	Claims map[string][]string

	appHandler func(http.ResponseWriter, *http.Request) error

	Provisioner struct {
		ConfigurationEndpoint string `json:"configurationEndpoint"`
	}

	Opconfig struct {
		Authorization        string `json:"authorization_endpoint"`
		Userinfo             string `json:"userinfo_endpoint"`
		Introspect           string `json:"introspection_endpoint"`
		Device_authorization string `json:"device_authorization_endpoint"`
		Token                string `json:"token_endpoint"`
		Issuer               string `json:"issuer"`
	}

	CAParams struct {
		Ttl         int64
		Permissions ssh.Permissions
	}

	ClientConfig struct {
		PublicKey string
	}

	CaConfig struct {
		OK, Fake, Hide                               bool
		SSOHost, Id, Name                            string
		SSHTemplate, HTMLTemplate                    string
		DefaultPrincipals, AuthnContextClassRef      []string
		AllowedFlows                                 []Flow
		HashedPrincipal                              bool
		MyAccessID, ResourcesMandatory               bool
		CAParams                                     CAParams
		Scope, EntitlementsNamespace                 string
		IntroSpectClientID, IntroSpectClientSecret   string
		IntroSpectConfigEndpoint, IntroSpectEndpoint string
		UserInfoEndpoint, UserInfoConfigEndpoint     string
		PublicKey                                    string
		OAuth2Config                                 *oauth2.Config
		Op, Iop                                      Opconfig   `json:"-"`
		Signer                                       ssh.Signer `json:"-"`
		MandatoryClaims, Claims                      map[string]string
	}

	Conf struct {
		ServiceName, RelayingParty string
		HostCertificatePrincipals  []string
		WWW                        embed.FS
		Template, HTMLTemplate     string
		Verification_uri_template  string
		SSOTTL, RendevouzTTL       string
		SshPort                    string
		SshListenOn                string
		WebListenOn                string
		UseRevProxy                bool
		CaConfigs                  map[string]CaConfig
		Cryptokilib                string
		Slot                       string
		NoOfSessions               int
	}

	myAccessIdParams struct {
		PublicKey string // don't use []byte - will be json interpreted as base64
		OTT       string
		Resource  string
	}

	certRec struct {
		SshCert       string `json:"ssh_cert,omitempty"`
		Resource      string `json:"resource,omitempty"`
		PosixUsername string `json:"posix_username,omitempty"`
	}

	secretsRec struct {
		SlotPin                 string
		ServerCert, ServerKey   []byte
		ClientSecrets           map[string]string
		IntroSpectClientSecrets map[string]string
	}
)

const (
	SSHFLOW = iota
	WEBFLOW
)

var (
	allowedKeyTypes = map[string]bool{
		"ssh-ed25519-cert-v01@openssh.com": true,
		"ssh-ed25519":                      true,
	}
	Config      Conf
	Secrets     secretsRec
	tmpl        *template.Template
	claimsStore = &rendezvous{}
	funcMap     = template.FuncMap{
		"PathEscape": url.PathEscape,
	}
	ssoTTL, rendevouzTTL    time.Duration
	ErrNoValidResourceFound = errors.New("You don't have permission for the requested Resource")
	hostCertTTL, _          = time.ParseDuration("720h")
	PublicKey               string
	Signer                  ssh.Signer
)

func Sshca(envJson []byte) {
	tmpl = template.Must(template.New("ca.template").Funcs(funcMap).Parse(Config.Template))
	ssoTTL, _ = time.ParseDuration(Config.SSOTTL)
	rendevouzTTL, _ = time.ParseDuration(Config.RendevouzTTL)
	claimsStore.ttl = rendevouzTTL
	claimsStore.cleanUp()
	Config.SshPort = Config.SshListenOn[strings.Index(Config.SshListenOn, ":")+1:]
	prepareCAs()
	go sshserver()

	http.HandleFunc("/favicon.ico", faviconHandler)
	http.Handle("/", appHandler(sshcaRouter))
	if Config.UseRevProxy {
		fmt.Println("Listening on port: " + Config.WebListenOn)
		err := http.ListenAndServe(Config.WebListenOn, nil)
		fmt.Println("err: ", err)
	} else {
		cert, _ := tls.X509KeyPair(Secrets.ServerCert, Secrets.ServerKey)
		s := &http.Server{
			Addr: Config.WebListenOn,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		}
		s.SetKeepAlivesEnabled(false)
		err := s.ListenAndServeTLS("", "")
		if err != nil {
			log.Printf("main(): %s\n", err)
		} else {
			log.Println("sshca stopped gracefully")
		}
	}
}

func faviconHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFileFS(w, r, Config.WWW, "/www/favicon.ico")
}

func sshcaRouter(w http.ResponseWriter, r *http.Request) (err error) {
	r.ParseForm()
	path := strings.Split(r.URL.Path+"//", "/")
	p, pp := path[1], path[2]
	switch p { // handle /www /feedback /sso
	case "www":
		http.ServeFileFS(w, r, Config.WWW, r.URL.Path)
		return
	case "feedback":
		return feedbackHandler(w, r)
	case "pwdevice": // returning from login
		return pwdeviceHandler(w, r)
	case "pw": // returning from login
		return pwHandler(w, r)
	case "acs", "acs2": // returning from login
		if ci, ok := claimsStore.get(r.Form.Get("state")); ok {
			return acsHandler(w, r, Config.CaConfigs[ci.ca])
		}
		return
	default:
		if ci, ok := claimsStore.get(p); ok { // see if it is a token
			return tokenHandler(w, r, p, ci)
		}
		ca, ok := Config.CaConfigs[p]
		if ok {
			// pp = pp
		} else if ca, ok = Config.CaConfigs[r.Host]; ok {
			pp = p
		} else {
			err = tmpl.ExecuteTemplate(w, "listCAs", map[string]any{"config": Config.CaConfigs})
			return
		}
		if !ca.OK {
			if slices.Contains([]string{"sign", "signJSON"}, pp) {
				return fmt.Errorf("The SSH CA for the %s is not available", ca.Name)
			}
			err = tmpl.ExecuteTemplate(w, ca.HTMLTemplate, map[string]any{"ca": ca, "err": fmt.Sprintf("The SSH CA for the %s is not available", ca.Name)})
			return
		}
		if r.Form.Get("code") != "" {
			return acsHandler(w, r, ca)
		}
		switch pp {
		case "config":
			jsonTxt, _ := json.Marshal(ClientConfig{PublicKey: ca.PublicKey})
			w.Header().Add("Content-Type", "application/json")
			w.Write(jsonTxt)
			return
		case "sign":
			return sshsignHandler(w, r, ca)
		case "signJSON":
			return sshsignHandlerJSON(w, r, ca)
		case "mindthegap":
			http.ServeFileFS(w, r, Config.WWW, "/www/mindthegap.html")
			return
		case "ri":
			return riHandler(w, r, ca)
		case "sso2":
			return sso2Handler(w, r, ca)
		case "acs", "acs2":
			return acsHandler(w, r, ca)
		default:
			err = tmpl.ExecuteTemplate(w, ca.HTMLTemplate, map[string]any{"ca": ca, "rp": Config.RelayingParty, "ri": "//" + r.Host + "/" + ca.Id + "/ri?"})
			return
		}
	}
}

func prepareCAs() {
	cas := slices.Sorted(maps.Keys(Config.CaConfigs))
	for _, k := range cas {
		v := Config.CaConfigs[k]
		if v.SSOHost != "" { // neeeded here because we need to look up by host even if the initialization fails
			Config.CaConfigs[v.SSOHost] = v
		}
		if v.HTMLTemplate == "" {
			v.HTMLTemplate = Config.HTMLTemplate
		}
		v.Id = k
		if Signer != nil {
			v.Signer = Signer
			v.PublicKey = PublicKey
		}
		if v.UserInfoConfigEndpoint != "" {
			fmt.Println("Get OIDC UserInfo config for:", v.Name)
			op := Opconfig{}
			resp, err := http.Get(v.UserInfoConfigEndpoint)
			if err != nil {
				fmt.Println("Failed ...")
				continue
			}
			configJson, _ := io.ReadAll(resp.Body)
			err = json.Unmarshal(configJson, &op)
			if err != nil {
				fmt.Println("Failed ...")
				continue
			}
			v.OAuth2Config.ClientSecret = Secrets.ClientSecrets[k]
			v.OAuth2Config.Endpoint.AuthURL = op.Authorization
			v.OAuth2Config.Endpoint.TokenURL = op.Token
			v.UserInfoEndpoint = op.Userinfo
		}
		if v.IntroSpectConfigEndpoint != "" {
			fmt.Println("Get OIDC Introspect config for:", v.Name)
			op := Opconfig{}
			resp, err := http.Get(v.IntroSpectConfigEndpoint)
			if err != nil {
				fmt.Println("Failed ...")
				continue
			}
			configJson, _ := io.ReadAll(resp.Body)
			err = json.Unmarshal(configJson, &op)
			if err != nil {
				fmt.Println("Failed ...")
				continue
			}
			v.OAuth2Config.ClientSecret = Secrets.ClientSecrets[k]
			v.OAuth2Config.Endpoint.AuthURL = op.Authorization
			v.OAuth2Config.Endpoint.TokenURL = op.Token
			v.IntroSpectClientSecret = Secrets.IntroSpectClientSecrets[k]
			v.IntroSpectEndpoint = op.Introspect
		}
		if v.Signer == nil {
			pubkey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(v.PublicKey))
			privkeyLabel := base64.RawURLEncoding.EncodeToString(pubkey.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)[:])
			fmt.Println("Find Private key for", v.Name)
			priv, ok := findPrivatekey(privkeyLabel)
			if !ok {
				fmt.Println("Failed ...")
				continue
			}
			v.Signer = hsmSigner{
				priv: priv,
				pub:  pubkey,
			}
		}
		v.OK = true
		if v.SSOHost != "" { // needed again - otherwise
			Config.CaConfigs[v.SSOHost] = v
		}
		if v.HTMLTemplate == "" {
			v.HTMLTemplate = Config.HTMLTemplate
		}
		Config.CaConfigs[k] = v
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
		} else if errors.Is(err, ErrNoValidResourceFound) {
			status = 403
		}
		http.Error(w, err.Error(), status)
	} else {
		err = fmt.Errorf("OK")
	}

	//log.Printf("%s: %s", err, r.Header.Get("User-Agent"))
	log.Printf("%s %s %s %+v %1.3f %d %s", remoteAddr, r.Method, r.Host, r.URL, time.Since(starttime).Seconds(), status, err)
}

func sso2Handler(w http.ResponseWriter, r *http.Request, ca CaConfig) (err error) {
	verifier := oauth2.GenerateVerifier()
	token := claimsStore.set("", certInfo{ca: ca.Id, verifier: verifier, eol: time.Now().Add(ssoTTL)})
	var auth strings.Builder
	auth.WriteString(ca.OAuth2Config.AuthCodeURL(token, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier)))
	for _, p := range []string{"idpentityid", "acr_values"} {
		if pv := r.Form.Get(p); pv != "" {
			auth.WriteString("&" + p + "=" + url.QueryEscape(pv))
		}
	}
	http.Redirect(w, r, auth.String(), http.StatusFound)
	return
}

func acsHandler(w http.ResponseWriter, r *http.Request, ca CaConfig) (err error) {
	r.ParseForm()
	code := r.Form.Get("code")
	ci, ok := claimsStore.get(r.Form.Get("state"))
	if !ok {
		return errors.New("unknown state")
	}

	ctx := context.Background()
	tok, err := ca.OAuth2Config.Exchange(ctx, code, oauth2.VerifierOption(ci.verifier))
	if err != nil {
		return errors.New("oauth exchange failed")
	}
	ci.claims, ci.resources, err = getUserInfo(tok.AccessToken, ca)
	if err != nil {
		return
	}
	// res map[string]interface {}{"error":"invalid_client"}
	ci.eol = time.Now().Add(rendevouzTTL)
	token := claimsStore.set("", ci)
	return ssoFinalize(w, r, token, ci)
}

func getUserInfo(token string, ca CaConfig) (claims Claims, resources []resource, err error) {
	data := url.Values{}
	data.Set("token", token)
	data.Set("client_id", ca.OAuth2Config.ClientID)
	data.Set("client_secret", ca.OAuth2Config.ClientSecret)

	request, _ := http.NewRequest("POST", ca.IntroSpectEndpoint, strings.NewReader(data.Encode()))
	if ca.UserInfoEndpoint != "" {
		request, _ = http.NewRequest("POST", ca.UserInfoEndpoint, strings.NewReader(data.Encode()))
		request.Header.Add("Authorization", "Bearer "+token)
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	responsebody, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	ui := map[string]any{}
	err = json.Unmarshal(responsebody, &ui)
	if err != nil {
		return nil, nil, errors.New("json parsing error")
	}
	claims = Claims{}
	if ca.Fake {
		claims["principal"] = []string{"a_really_fake_principal"}
	} else {
		claims, err = claimsC14n(ca, ui)
		if err != nil {
			return
		}
	}
	resources = getEFPResources(ca.EntitlementsNamespace, claims["entitlements"])
	return
}

func claimsC14n(ca CaConfig, claims map[string]any) (canonicalClaims map[string][]string, err error) {
	canonicalClaims = map[string][]string{}
	for c14n, n := range ca.MandatoryClaims {
		canonicalClaims[c14n] = []string{}
		if claim, ok := claims[n]; ok {
			if p, ok := claim.(string); ok {
				canonicalClaims[c14n] = append(canonicalClaims[c14n], p)
			} else if p, ok := claim.([]any); ok {
				for _, val := range p {
					if v, ok := val.(string); ok {
						canonicalClaims[c14n] = append(canonicalClaims[c14n], v)
					} else {
						return nil, fmt.Errorf("Mandatory claim of unsupported type %s", n)
					}
				}
			} else {
				return nil, fmt.Errorf("Mandatory claim of unsupported type %s", n)
			}
		} else {
			return nil, fmt.Errorf("Mandatory claim missing: %s", n)
		}
	}
	for n, c14n := range ca.Claims {
		canonicalClaims[c14n] = []string{}
		if claim, ok := claims[n]; ok {
			if p, ok := claim.(string); ok {
				canonicalClaims[c14n] = append(canonicalClaims[c14n], p)
			} else if p, ok := claim.([]any); ok {
				for _, val := range p {
					if v, ok := val.(string); ok {
						canonicalClaims[c14n] = append(canonicalClaims[c14n], v)
					} else {
						return nil, fmt.Errorf("Optional claim of unsupported type %s", n)
					}
				}
			} else {
				return nil, fmt.Errorf("Optional claim of unsupported type %s", n)
			}
		}
	}
	return
}

func riHandler(w http.ResponseWriter, r *http.Request, ca CaConfig) (err error) {
	r.ParseForm()
	ci := certInfo{ca: ca.Id, eol: time.Now().Add(ssoTTL)}
	if ca.Fake {
		ci.claims = Claims{"principal": []string{"a_really_fake_principal"}}
		token := claimsStore.set("", ci)
		return ssoFinalize(w, r, token, ci)
	}
	token := claimsStore.set("", ci)
	data := url.Values{}
	data.Set("state", token)
	if idp := r.Form.Get("entityID"); idp != "" {
		data.Set("idpentityid", idp)
	}
	if len(ca.AuthnContextClassRef) > 0 {
		data.Set("acr_values", strings.Join(ca.AuthnContextClassRef, " "))
	}

	http.Redirect(w, r, "//"+ca.SSOHost+"/"+ca.Id+"/sso2?"+data.Encode(), http.StatusFound)
	return
}

func tokenHandler(w http.ResponseWriter, r *http.Request, token string, ci certInfo) (err error) {
	ca := Config.CaConfigs[ci.ca]
	ci.eol = time.Now().Add(ssoTTL)
	claimsStore.set(token, ci)
	data := url.Values{}
	data.Set("state", token)
	if ci.idp != "" {
		data.Set("idpentityid", ci.idp)
	}
	if len(ca.AuthnContextClassRef) > 0 {
		data.Set("acr_values", strings.Join(ca.AuthnContextClassRef, " "))
	}
	http.Redirect(w, r, "//"+ca.SSOHost+"/sso?"+data.Encode(), http.StatusFound)
	return
}

func pwdeviceHandler(w http.ResponseWriter, r *http.Request) (err error) {
	r.ParseForm()
	token := r.Form.Get("state")
	waitfor := principal
	if ci, ok := claimsStore.get(token); ok && ci.pw != "" {
		waitfor = principalAndPassword
	}
	if ci, ok := claimsStore.wait(token, waitfor); ok {
		return ssoFinalize(w, r, token, ci)
	}
	return
}

func ssoFinalize(w http.ResponseWriter, r *http.Request, token string, ci certInfo) (err error) {
	ca := Config.CaConfigs[ci.ca]
	if len(ci.claims["principal"]) > 0 {
		wantedAcrs := ca.AuthnContextClassRef
		acrs := []string{}
		for _, n := range []string{"acr", "edupersonassurance"} {
			if claims, ok := ci.claims[n]; ok && len(claims) > 0 {
				acrs = append(acrs, strings.Split(ci.claims[n][0], ",")...)
			}
		}
		if len(wantedAcrs) > 0 && intersectionEmpty(wantedAcrs, acrs) {
			tmpl.ExecuteTemplate(w, ca.HTMLTemplate, map[string]any{"err": fmt.Sprintf("No valid AuthnContextClassRef/acr found wanted: %v got: %v", wantedAcrs, acrs)})
			return
		}
		if ci.pw != "" {
			if tmp, err := r.Cookie("pw"); err != nil || tmp.Value != ci.pw {
				ci.pwparam = rand.Text()
				claimsStore.set(token, ci)
				http.SetCookie(w, &http.Cookie{Name: "pw", Path: "/", Secure: true, HttpOnly: true, MaxAge: -1, SameSite: http.SameSiteStrictMode})
				err = tmpl.ExecuteTemplate(w, "pw", map[string]any{"token": token, "pwparam": ci.pwparam})
				return err
			}
			ci.pw = ""
			claimsStore.set(token, ci)
			err = tmpl.ExecuteTemplate(w, "certificate", map[string]any{"token": token})
			return
		}
		if ca.ResourcesMandatory && len(ci.resources) == 0 {
			err = tmpl.ExecuteTemplate(w, ca.HTMLTemplate, map[string]any{"err": "Unfortunately, you do not have access to the EuroHPC Federation Platform."})
			return
		}
		err = tmpl.ExecuteTemplate(w, ca.HTMLTemplate, map[string]any{"ci": ci, "ca": ca, "state": token, "sshport": Config.SshPort, "rp": Config.RelayingParty, "ri": "//" + r.Host + "/" + ca.Id + "/ri?", "resources": ci.resources})
	}
	return
}

func pwHandler(w http.ResponseWriter, r *http.Request) (err error) {
	path := strings.Split(r.URL.Path+"//", "/")
	token := path[2]
	defer r.Body.Close()
	r.ParseForm()
	if ci, ok := claimsStore.get(token); ok {
		if ci.pw == r.Form.Get(ci.pwparam) {
			http.SetCookie(w, &http.Cookie{Name: "pw", Value: ci.pw, Path: "/", Secure: true, HttpOnly: true, MaxAge: 86400, SameSite: http.SameSiteLaxMode})
			ci.pw = ""
			claimsStore.set(token, ci)
			err = tmpl.ExecuteTemplate(w, "certificate", map[string]any{"token": token})
		} else {
			ci.pwparam = rand.Text()
			claimsStore.set(token, ci)
			err = tmpl.ExecuteTemplate(w, "pw", map[string]any{"token": token, "pwparam": ci.pwparam})
		}
	}
	return
}

func feedbackHandler(w http.ResponseWriter, r *http.Request) (err error) {
	path := strings.Split(r.URL.Path+"//", "/")
	token := path[2]
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")

	ticker := time.NewTicker(1 * time.Second)
	for {
		<-ticker.C
		ci, ok := claimsStore.get(token)
		if !ok {
			fmt.Fprint(w, "event: cancel\ndata: none\n\n")
			w.(http.Flusher).Flush()
			return
		}
		if ci.cert == nil {
			fmt.Fprint(w, "event: wait\ndata: none\n\n")
			w.(http.Flusher).Flush()
			continue
		}
		fmt.Fprintf(w, "event: certready\n%s\n\n", certPP(ci.cert, "data: "))
		w.(http.Flusher).Flush()
		return
	}
}

func sshsignHandler(w http.ResponseWriter, r *http.Request, ca CaConfig) (err error) {
	sshCertificate, _, err := sshsign(w, r, ca)
	if err != nil {
		return
	}
	cert := ssh.MarshalAuthorizedKey(sshCertificate)
	w.Write(cert)
	log.Println("sign", ca.Id, string(cert))
	return
}

func sshsignHandlerJSON(w http.ResponseWriter, r *http.Request, ca CaConfig) (err error) {
	sshCertificate, res, err := sshsign(w, r, ca)
	if err != nil {
		return
	}
	cert := string(ssh.MarshalAuthorizedKey(sshCertificate))
	rec := certRec{
		SshCert:       cert,
		Resource:      res.Resource,
		PosixUsername: res.Uid,
	}
	resJSON, _ := json.Marshal(rec)
	w.Write(resJSON)
	log.Println("signJSON", ca.Id, cert)
	return
}

func sshsign(w http.ResponseWriter, r *http.Request, ca CaConfig) (sshCertificate *ssh.Certificate, res resource, err error) {
	params := myAccessIdParams{}
	defer r.Body.Close()
	r.ParseForm()
	if !slices.Contains(ca.AllowedFlows, WEBFLOW) {
		err = fmt.Errorf("webflow flow not enabled for this ca")
		return
	}
	req, _ := io.ReadAll(r.Body)
	err = json.Unmarshal(req, &params)
	if err != nil {
		fmt.Println("err", err)
		return
	}
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(params.PublicKey))
	if err != nil {
		return
	}

	claims, resources, err := getUserInfo(params.OTT, ca)
	if err != nil {
		return
	}

	i := slices.IndexFunc(resources, func(r resource) bool { return r.Resource == params.Resource })
	if i < 0 { // no resources from getUserIfo -> no access
		err = fmt.Errorf("unknown resource %s", params.Resource)
		return
	}
	res = resources[i]

	ci := certInfo{ca: ca.Id, claims: claims, resources: resources}
	sshCertificate, err = newCertificate(ca, publicKey, ci, []string{params.Resource})
	if err != nil {
		return
	}
	return
}

func sshserver() {
	sshConfig := &ssh.ServerConfig{
		Config: ssh.Config{
			MACs: ssh.SupportedAlgorithms().MACs,
		},
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
	hostSigner, err := newHostSigner(Config.CaConfigs["transport"].Signer, Config.ServiceName, Config.HostCertificatePrincipals)
	if err != nil {
		log.Fatal("failed to create hostSigner: ", err)
	}
	sshConfig.AddHostKey(hostSigner)
	sshConfig.AddHostKey(Config.CaConfigs["transport"].Signer)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", Config.SshListenOn)
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	fmt.Println("ssh listening on " + Config.SshListenOn)

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
	conn, chans, reqs, err := ssh.NewServerConn(nConn, sshConfig)
	if err != nil {
		log.Println("failed to handshake: ", err)
		return
	}
	defer conn.Close()

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
				resourcesList := []int{}
				args := strings.Split(string(req.Payload[4:])+"  ", " ") // always at least 2 elements
				f1 := flag.NewFlagSet("", flag.ExitOnError)
				ca := f1.String("ca", "", "")
				idp := f1.String("idp", "", "")
				pw := f1.String("pw", "", "")
				f1.Parse(args[1:])
				token := f1.Arg(0)
				cmd := args[0]
				//				fmt.Printf("sshd cmd: %s ca: %s idp: %s pw: %s resource: %s token: %s\n", cmd, *ca, *idp, *pw, *resource, token)
				switch cmd {
				case "demo":
					demoCert(channel, publicKey)
					channel.Close()
					return
				case "ca":
					caConfig, ok := Config.CaConfigs[*ca]
					if *ca != "" && !ok {
						io.WriteString(channel, "unknown ca\n")
						channel.Close()
						return
					}
					if !slices.Contains(caConfig.AllowedFlows, SSHFLOW) {
						io.WriteString(channel, "ssh flow not enabled for this ca\n")
						channel.Close()
						return
					}
					if len(*pw) < 15 {
						io.WriteString(channel, "pw to short - min 15 chars\n")
						channel.Close()
						return
					}
					token = claimsStore.set("", certInfo{ca: *ca, idp: *idp, pw: *pw, eol: time.Now().Add(rendevouzTTL)})
					io.WriteString(channel, fmt.Sprintf(Config.Verification_uri_template, caConfig.SSOHost, token))
				case "token", "token2":
					tmp := strings.Split(strings.Trim(token, " ")+"-", "-") // always at least 2 elements
					token = tmp[0]
					if matched, _ := regexp.MatchString(`^[A-Z]?$`, strings.Trim(tmp[1], " ")); !matched {
						io.WriteString(channel, "unknown resources\n")
						channel.Close()
						return
					}
					for _, r := range tmp[1] {
						i := int(r) - int('A')
						resourcesList = append(resourcesList, i)
					}
				}
				ci, ok := claimsStore.wait(token, principal)
				if ok && user != "" && ci.cert == nil {
					posixUsernames := []string{}
					resources := []string{}
					for _, r := range resourcesList {
						if r >= len(ci.resources) {
							channel.Close()
							return
						}
						resources = append(resources, ci.resources[r].Resource)
						posixUsernames = append(posixUsernames, ci.resources[r].Uid)
					}
					ca := Config.CaConfigs[ci.ca]
					cert, err := newCertificate(ca, publicKey, ci, resources)
					if err == nil {
						certTxt := string(ssh.MarshalAuthorizedKey(cert))
						log.Println("ssh", ca.Id, certTxt)
						if cmd == "token2" {
							res := certRec{
								SshCert:       certTxt,
								Resource:      resources[0],
								PosixUsername: posixUsernames[0],
							}
							resJSON, _ := json.Marshal(res)
							fmt.Fprintf(channel, "%s\n", resJSON)
						} else {
							fmt.Fprintf(channel, "%s", certTxt)
						}
						ci.cert = cert
						claimsStore.set(token, ci) // for feedback to browser
					}
				}
				channel.Close()
			case "shell":
				fmt.Fprintf(channel, "%s\n", "Access Denied")
				channel.Close()
			}
		}
	}
}

func newHostSigner(signer ssh.Signer, keyId string, principals []string) (hostSigner ssh.Signer, err error) {
	now := time.Now().In(time.FixedZone("UTC", 0)).Unix()
	cert := &ssh.Certificate{
		CertType:        ssh.HostCert,
		Key:             signer.PublicKey(),
		KeyId:           keyId,
		ValidPrincipals: principals,
		ValidAfter:      uint64(now - 60),
		ValidBefore:     uint64(now) + uint64(hostCertTTL),
	}
	err = cert.SignCert(rand.Reader, signer)
	return ssh.NewCertSigner(cert, signer)
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

func newCertificate(ca CaConfig, pubkey ssh.PublicKey, ci certInfo, resources []string) (cert *ssh.Certificate, err error) {
	if _, ok := pubkey.(*ssh.Certificate); ok {
		pubkey = pubkey.(*ssh.Certificate).Key
	}
	params := ca.CAParams
	if len(resources) > 0 {
		res, _ := json.Marshal(resources)
		params.Permissions.Extensions = maps.Clone(params.Permissions.Extensions)
		// arams.Permissions.Extensions["ssh-domain-grant@core.aai.geant.org"+res] = "" //`["` + res + `"]` // experiment with data as key - lets ssh-keyget -L -f - show it as text
		params.Permissions.Extensions["ssh-domain-grant@core.aai.geant.org"] = string(res)
	}
	if username := usernameFromPrincipal(ci.claims["principal"][0], ca); username != "" {
		ci.claims["principal"] = append(ci.claims["principal"], username)
	}
	now := time.Now().In(time.FixedZone("UTC", 0)).Unix()
	cert = &ssh.Certificate{
		CertType:        ssh.UserCert,
		Serial:          uint64(time.Now().UnixNano()),
		Key:             pubkey,
		Permissions:     params.Permissions,
		KeyId:           ci.claims["principal"][0],
		ValidPrincipals: ci.claims["principal"],
		ValidAfter:      uint64(now - 60),
		ValidBefore:     uint64(now + params.Ttl),
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
		username = strings.ReplaceAll(principal[:36], "-", "")
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

// PP - super simple Pretty Print - using JSON
func PP(i ...any) {
	for _, e := range i {
		switch v := e.(type) {
		case []byte:
			fmt.Println(string(v))
		default:
			s, _ := json.MarshalIndent(v, "", "    ")
			fmt.Println(string(s))
		}
	}
}

// rendezvous

const (
	principal = iota
	certificate
	principalAndPassword
)

type (
	resource struct {
		Resource, Uid string
	}

	certInfo struct {
		ca        string
		idp       string
		pw        string
		pwparam   string
		verifier  string
		claims    Claims
		resources []resource
		cert      *ssh.Certificate
		eol       time.Time
	}

	rendezvous struct {
		info sync.Map
		ttl  time.Duration
	}
)

func (rv *rendezvous) cleanUp() {
	ticker := time.NewTicker(rendevouzTTL)
	go func() {
		for {
			<-ticker.C
			rv.info.Range(func(k, v any) bool {
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
		token = rand.Text()
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

func (rv *rendezvous) wait(token string, cond int) (ci certInfo, ok bool) {
	ticker := time.NewTicker(time.Second)
	for {
		ci, ok = rv.get(token)
		if !ok {
			return
		}
		principals := len(ci.claims["principal"]) > 0
		if (cond == principal && principals && ci.pw == "") || (cond == certificate && ci.cert != nil) || (cond == principalAndPassword && principals && ci.pw != "") {
			return
		}
		<-ticker.C
	}
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
	for _, s := range s1 {
		if slices.Index(s2, s) >= 0 {
			return false
		}
	}
	return true
}

func GetConfig(envJson []byte, pw string) (secrets secretsRec) {
	var key [32]byte
	keySlice, _ := base64.RawStdEncoding.DecodeString(pw)
	copy(key[:], keySlice[:32])

	var decryptNonce [24]byte
	copy(decryptNonce[:], envJson[:24])
	decrypted, ok := secretbox.Open(nil, envJson[24:], &decryptNonce, &key)
	if !ok {
		panic("decryption error")
	}
	secrets = secretsRec{}
	err := json.Unmarshal(decrypted, &secrets)
	if err != nil {
		log.Panic(err)
	}
	return
}

// EFP

func getEFPResources(namespace string, values []string) (resources []resource) {
	if namespace != "" {
		for _, val := range values {
			if tmp, ok := strings.CutPrefix(val, namespace); ok {
				if tmp, ok := strings.CutSuffix(tmp, ":act:ssh"); ok {
					tmp2 := strings.Split(tmp+":", ":") // always at least 2 elements
					for i := range tmp2 {
						if v, e := url.QueryUnescape(tmp2[i]); e == nil { // ignore errors for now ...
							tmp2[i] = v
						}
					}
					resources = append(resources, resource{Resource: tmp2[0], Uid: tmp2[1]})
				}
			}
		}
		// resources = append(resources, resource{Resource: "", Uid: ""})
	}
	return
}
