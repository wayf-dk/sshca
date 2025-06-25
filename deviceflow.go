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
	resp, err := device_authorization_request(ca.ClientID, ca.Op.Device_authorization)
	if err != nil {
		return
	}
    tmpl.ExecuteTemplate(w, "deviceflow", map[string]any{"state": token, "verification_uri": resp["verification_uri_complete"].(string)})
    go func(token string) {
		tokenResponse, _ := token_request(ca, resp["device_code"].(string))
		if tokenResponse != nil {
            resp, err := introspect(tokenResponse["access_token"].(string), ca)
            if err != nil {
                return
            }
            if val, ok := resp["sub"].(string); ok {
                setPrincipal(token, val)
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

func token_request(ca CaConfig, device_code string) (res map[string]any, err error) {
	v := url.Values{}
	v.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	v.Set("device_code", device_code)
	v.Set("client_id", ca.ClientID)
	tries := 10
	timeout := 2 * time.Second
	for tries > 0 {
		tries--
		resp, err := client.PostForm(ca.Op.Token, v)
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
