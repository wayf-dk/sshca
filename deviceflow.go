package sshca

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

func deviceflowHandler(w http.ResponseWriter, caConfig CaConfig, token string) (err error) {
    resp, err := device_authorization_request(caConfig.ClientID, caConfig.Op.Device_authorization)
    fmt.Println("dev flow", resp, err)
    if err != nil {
        return
    }
    claims.set(token+"_feedback", certInfo{})
    tmpl.ExecuteTemplate(w, "login", map[string]string{"ca": caConfig.Name, "state": token, "sshport": Config.SshPort, "verification_uri": resp["verification_uri_complete"].(string)})
    go func(token string) {
        tokenResponse, err := token_request(caConfig.ClientID, caConfig.Op.Token, resp["device_code"].(string))
        fmt.Println("tok resp", tokenResponse, err)
        if tokenResponse != nil {
            userInfo, err := getUserinfo(tokenResponse["access_token"].(string), caConfig.Op.Userinfo)
            if err != nil {
                return
            }
            claims.meet(token, certInfo{claims: userInfo})
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
	fmt.Println("token", token)
	tries := 10
	timeout := 2 * time.Second
	for tries > 0 {
		tries--
		resp, err := client.PostForm(token, v)
        fmt.Println("tok req", v, resp, tries, err)
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
