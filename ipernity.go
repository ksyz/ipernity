// Package ipernity provides a basic golang API to the ipernity photo sharing site

package ipernity

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sort"
)

// result of ipernity auth.getfrob api call
type Authgetfrob struct {
	Auth struct {
		Frob string `json:"frob"`
	}
	Api struct {
		Status  string `json:"status"`
		At      string `json:"at"`
		Code    string `json:"code"`    // only if status != "ok"
		Message string `json:"message"` // only if status != ok
	}
}

// result of ipernity auth.getToken api call
type Authgettoken struct {
	Auth struct {
		Token       string `json:"token"`
		Permissions struct {
			Doc     string `json:"doc"`
			Blog    string `json:"blog"`
			Profile string `json:"profile"`
			Network string `json:"network"`
			Post    string `json:"post"`
		}
		User struct {
			User_id  string `json:"user_id"`
			Username string `json:"username"`
			Realname string `json:"realname"`
			Lg       string `json:"lg"`
			Is_pro   string `json:"is_pro"`
		}
	}
	Api struct {
		Status  string `json:"status"`
		At      string `json:"at"`
		Code    string `json:"code"`    // only if status != "ok"
		Message string `json:"message"` // only if status != ok
	}
}

// a parameter to an ipernity api call
type Parameter struct {
	name  string
	value string
}

// a slice of parameters
type pslice []Parameter

const (
	apikey    = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" // API Key, a constant obtained from ipernity
	apisecret = "YYYYYYYYYYYYYYYY"                 // API Secret, a constant obtained from ipernity
	tokenfile = "ipernity_auth_token"              // Filename where ipernity token is cached
)

var (
	token   = "" // token, either retrieved from local cache or retrieved from ipernity via api call
	user_id = "" // your ipernity user id
)

// Len is part of sort.Interface
func (p pslice) Len() int {
	return len(p)
}

// Less is part of sort.Interface
func (p pslice) Less(i, j int) bool {
	return p[i].name < p[j].name
}

// Swap is part of sort.Interface
func (p pslice) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

// Sign an ipernity api request with the md5 signature
func signRequest(request string) string {
	return fmt.Sprintf("%32x", md5.Sum([]byte(request)))
}

// call ipernity auth.getFrob api
func call_auth_getFrob() Authgetfrob {
	var (
		parms pslice
	)

	parms = append(parms, Parameter{"api_key", apikey})
	f := callApiMethod(parms, "auth.getFrob")
	jsonresult := &Authgetfrob{}
	json.Unmarshal(f, &jsonresult)

	if jsonresult.Api.Status != "ok" {
		fmt.Println("Error getting frob: " + jsonresult.Api.Code + " " + jsonresult.Api.Message)
	}

	return *jsonresult
}

// call ipernity auth.getToken api
func call_auth_getToken(frob string) Authgettoken {
	var (
		parms pslice
	)

	parms = append(parms, Parameter{"api_key", apikey}, Parameter{"frob", frob})
	f := callApiMethod(parms, "auth.getToken")
	jsonresult := &Authgettoken{}
	json.Unmarshal(f, &jsonresult)

	if jsonresult.Api.Status != "ok" {
		fmt.Println("Error getting frob: " + jsonresult.Api.Code + " " + jsonresult.Api.Message)
	}
	user_id = jsonresult.Auth.User.User_id

	return *jsonresult
}

// call an ipernity api method
func callApiMethod(parameters pslice, method string) []byte {
	var (
		encodedval string
		signparams string
		urlparams  string
	)

	sort.Sort(parameters)

	for _, p := range parameters {
		encodedval = url.QueryEscape(p.value)
		signparams += p.name + encodedval
		urlparams += p.name + "=" + encodedval + "&"
	}
	urlparams += "api_sig=" + signRequest(signparams+method+apisecret)

	//	fmt.Println(urlparams)
	resp, err := http.Post("http://api.ipernity.com/api/"+method+"/json", "application/x-www-form-urlencoded", bytes.NewBufferString(urlparams))
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	//	fmt.Println(string(body))

	if err != nil {
		panic(err)
	}

	return body
}

// return URL user must visit to authorize this program to talk to ipernity
func getAuthUrl(frob string) string {
	var (
		encodedval string
		signparams string
		urlparams  string
		parameters pslice
	)

	parameters = append(parameters, Parameter{"api_key", apikey}, Parameter{"frob", frob}, Parameter{"api_secret", apisecret},
		Parameter{"perm_doc", "write"}, Parameter{"perm_blog", "write"})

	sort.Sort(parameters)

	for _, p := range parameters {
		encodedval = url.QueryEscape(p.value)
		signparams += p.name + encodedval
		urlparams += p.name + "=" + encodedval + "&"
	}

	urlparams += "api_sig=" + signRequest(signparams+apisecret)
	return "http://www.ipernity.com/apps/authorize?" + urlparams
}

// log in to ipernity
func Login() error {
	// see if we have a token file

	data, err := ioutil.ReadFile(tokenfile)

	if err != nil {
		frob := call_auth_getFrob()
		if frob.Api.Status != "ok" {
			panic(err)
		}
		fmt.Println("go to " + getAuthUrl(frob.Auth.Frob))
		fmt.Println("and grant the permissions, then press <ENTER>")
		consolereader := bufio.NewReader(os.Stdin)
		input, err := consolereader.ReadString('\n')
		input = input

		tokenjson := call_auth_getToken(frob.Auth.Frob)
		if tokenjson.Api.Status != "ok" {
			panic(err)
		}
		token = tokenjson.Auth.Token
		err = ioutil.WriteFile(tokenfile, []byte(token), 0644)
		if err != nil {
			panic(err)
		}
	} else {
		token = string(data)
	}

	return nil
}
