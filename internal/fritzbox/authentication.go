package fritzbox

import (
	"crypto/md5" // nolint: gas
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"io"
//  "crypto/sha256"
//  "crypto/aes"
	"encoding/hex"
//	"golang.org/x/crypto/pbkdf2"
	"net/http"
	"strings"
	"strconv"
)

type loginState struct {
	challenge string
	blocktime string
}

func (si *SessionInfo) is_pbkdf2() bool {
	return strings.HasPrefix(si.Challenge, "2$")
}

// PerformLogin performs a login and returns SessionInfo including
// the session id (SID) on success
func (fb *FritzBox) PerformLogin(adminPassword string) error {
	client := fb.getHTTPClient()

	session, err := fetchSessionInfo(client, fb.Host+"/login_sid.lua?version=2")
	if err != nil {
		return err
	}
	fmt.Printf("SessionInfo: %v\n", session)

	if session.is_pbkdf2() {
		log.Printf("session is pbkdf2\n")
		response = buildPbkdf2Response(session.Challenge, adminPassword)
	} else {
		// fallback to md4
	}

	response := buildResponse(session.Challenge, adminPassword)

	_url := fb.Host + "/login_sid.lua?username="+fb.User+"&response=" + response
	log.Printf("url = '%s'\n", _url)

	session, err = fetchSessionInfo(client, _url)
	if err != nil {
		fmt.Printf("failed to fetch Session Info err:%v\n", err)
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

func buildPbkdf2Response(challenge string, password string) string {
	_challenge_parts := strings.Split(challenge, "$")
	_iter1 := strconv.Atoi(_challenge_parts[1])
	_salt1 := hex.DecodeString(_challenge_parts[2])
	_iter2 := strconv.Atoi(_challenge_parts[3])
	_salt2 := hex.DecodeString(_challenge_parts[4])

	return ""
}
