package sshca

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

func deviceflowHandler(w http.ResponseWriter, r *http.Request, ca CaConfig) (err error) {
	token := claims.set("", certInfo{ca: ca.Id})
	resp, err := device_authorization_request(ca.ClientID, ca.Op.Device_authorization)
	if err != nil {
		return
	}
	tmpl.ExecuteTemplate(w, ca.HTMLTemplate, map[string]any{"ca": ca, "state": token, "sshport": Config.SshPort, "verification_uri": resp["verification_uri_complete"].(string), "op": ca.Id, "rp": Config.RelayingParty, "ri": "//" + r.Host + "/" + ca.Id + "/ri"})
	go func(token string) {
		tokenResponse, _ := token_request(ca.ClientID, ca.Op.Token, resp["device_code"].(string))
		if tokenResponse != nil {
			userInfo, err := getUserinfo(tokenResponse["access_token"].(string), ca.Op.Userinfo)
			if err != nil {
				return
			}
			val, ok := userInfo["sub"].(string)
			if ok {
				ci := certInfo{ca: ca.Id, principal: val, username: usernameFromPrincipal(val, ca), eol: time.Now().Add(rendevouzTTL)}
				claims.set(token, ci)
			}
		}
	}(token)
	return
}

func device_authorization_request(clientID, device_authorization string) (res map[string]any, err error) {
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("scope", "openid email profile eduperson_entitlement")
	resp, err := client.PostForm(device_authorization, v)
	if err != nil {
		return
	}
	responsebody, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	res = map[string]any{}
	json.Unmarshal(responsebody, &res)
	return
}

func token_request(clientID, token, device_code string) (res map[string]any, err error) {
	v := url.Values{}
	v.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	v.Set("device_code", device_code)
	v.Set("client_id", clientID)
	tries := 10
	timeout := 2 * time.Second
	for tries > 0 {
		tries--
		resp, err := client.PostForm(token, v)
		if err != nil {
			return nil, err
		} else if 200 <= resp.StatusCode && resp.StatusCode < 300 {
			responsebody, _ := io.ReadAll(resp.Body)
			res = map[string]any{}
			json.Unmarshal(responsebody, &res)
			return res, nil
		} else {
			time.Sleep(timeout)
			continue
		}
	}
	return nil, errors.New("")
}

func getUserinfo(token, endpoint string) (res map[string]any, err error) {
	request, _ := http.NewRequest("POST", endpoint, nil)
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Authorization", "Bearer "+token)
	resp, err := client.Do(request)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	responsebody, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	res = map[string]any{}
	json.Unmarshal(responsebody, &res)
	return
}
