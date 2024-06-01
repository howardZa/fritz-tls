package fritzbox

import (
	"crypto/md5" // nolint: gas
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"io"
	"net/http"
	"strings"
)

// PerformLogin performs a login and returns SessionInfo including
// the session id (SID) on success
func (fb *FritzBox) PerformLogin(adminPassword string) error {
	client := fb.getHTTPClient()

	session, err := fetchSessionInfo(client, fb.Host+"/login_sid.lua")
	if err != nil {
		return err
	}

	response := buildResponse(session.Challenge, adminPassword)

	log.Printf("fbUser %s", fb.User)
	session, err = fetchSessionInfo(client, fb.Host+"/login_sid.lua?&username="+fb.User+"&response="+response)
	if err != nil {
		return err
	}
	if session.SID == "0000000000000000" {
		return errors.New("login not successful")
	}

	fb.session = session

	return nil
}

func (fb *FritzBox) CheckSession() (bool, error) {
	client := fb.getHTTPClient()

	requestBody := strings.NewReader("sid=" + fb.session.SID)

	resp, err := client.Post(fb.Host+"/login_sid.lua?version=2", "application/x-www-form-urlencoded", requestBody)
	if err != nil {
		return false, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close() // nolint: errcheck

	var sessionInfo SessionInfo
	err = xml.Unmarshal(body, &sessionInfo)
	if err != nil {
		return false, err
	}

	return sessionInfo.SID == fb.session.SID, nil
}

func fetchSessionInfo(client *http.Client, url string) (SessionInfo, error) {
	resp, err := client.Get(url)
	if err != nil {
		return SessionInfo{}, err
	}

	defer resp.Body.Close() // nolint: errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return SessionInfo{}, err
	}

	var sessionInfo SessionInfo
	err = xml.Unmarshal(body, &sessionInfo)
	if err != nil {
		return SessionInfo{}, err
	}

	return sessionInfo, nil
}

func buildResponse(challenge string, password string) string {
	challengePassword := utf8ToUtf16(challenge + "-" + password)

	md5Response := md5.Sum([]byte(challengePassword)) // nolint: gas

	return challenge + "-" + fmt.Sprintf("%x", md5Response)
}
