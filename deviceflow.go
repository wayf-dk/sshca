package sshca

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

func deviceflowHandler(w http.ResponseWriter, r *http.Request, token string, ca CaConfig, ci certInfo) (err error) {
	resp, err := device_authorization_request(ca.ClientID, ca.Op.Device_authorization, ca.Scopes)
	if err != nil {
		return
	}
	tmpl.ExecuteTemplate(w, "deviceflow", map[string]any{"state": token, "verification_uri": resp.Verification_uri_complete})
	go func(token string) {
		tokenResponse, err := token_request(ca, resp)
		if err == nil {
			resp, err := introspect(tokenResponse.Access_token, ca)
			if err != nil {
				return
			}
			if ci, ok := claims.get(token); ok {
				claims.set(token, getMyAccssIdCertInfo(ci, resp))
			}
		}
	}(token)
	return
}

func device_authorization_request(clientID, device_authorization, scopes string) (res DeviceResponse, err error) {
	v := url.Values{}
	v.Set("client_id", clientID)
        v.Set("scope", scopes)
	resp, err := client.PostForm(device_authorization, v)
	if err != nil {
		return
	}

	responsebody, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	res = DeviceResponse{}
	json.Unmarshal(responsebody, &res)
	return
}

func token_request(ca CaConfig, deviceResponse DeviceResponse) (res TokenResponse, err error) {
	v := url.Values{}
	v.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	v.Set("device_code", deviceResponse.Device_code)
	v.Set("client_id", ca.ClientID)
	tries := 10
	timeout := 2 * time.Second
	if deviceResponse.Interval != 0 {
		timeout = deviceResponse.Interval * time.Second
	}
	for tries > 0 {
		tries--
		resp, err := client.PostForm(ca.Op.Token, v)
		if err != nil {
			return res, err
		} else if 200 <= resp.StatusCode && resp.StatusCode < 300 {
			responsebody, _ := io.ReadAll(resp.Body)
			res = TokenResponse{}
			json.Unmarshal(responsebody, &res)
			return res, nil
		} else {
			time.Sleep(timeout)
			continue
		}
	}
	return res, errors.New("")
}
