package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/hunkeelin/klinutils"
	"io/ioutil"
	"net/http"
	"time"
)

type respBody struct {
	Cert         []byte `json:"cert"`
	ChainOfTrust []byte `json:"chainoftrust"`
}

// Creates a new file upload http request with optional extra params
func newfileUploadRequest(uri string, csr []byte) (*http.Request, error) {
	//	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(csr))
	req, err := http.NewRequest("POST", uri, bytes.NewReader(csr))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, err
}

func getcrtv2(g WriteInfo, csrbytes []byte) (*respBody, error) {
	var p respBody
	var dest string
	if g.CA != "" {
		masteraddr, err := klinutils.GetHostnameFromCertv2(g.CA)
		if err != nil {
			return &p, err
		}
		dest = masteraddr
	} else {
		if g.CAName == "" {
			return &p, errors.New("Please specify name of the CA")
		}
		dest = g.CAName
	}
	i := &reqInfo{
		Dest:       dest,
		Dport:      g.CAport,
		Trust:      g.CA,
		TrustBytes: g.CABytes,
		Method:     "POST",
		Headers: map[string]string{
			"content-type": "application/x-www-form-urlencoded",
			"SignCA":       g.SignCA,
		},
		BodyBytes: csrbytes,
		TimeOut:   1500,
	}
	resp, err := sendPayload(i)
	if err != nil {
		return &p, err
	}
	body := &bytes.Buffer{}
	_, err = body.ReadFrom(resp.Body)
	if err != nil {
		return &p, err
	}
	resp.Body.Close()
	b := body.Bytes()
	if resp.StatusCode != 200 {
		return &p, errors.New(body.String())
	}
	err = json.Unmarshal(b, &p)
	if err != nil {
		return &p, err
	}
	return &p, nil
}
func Getcrt(m, host string, csr []byte) (*respBody, error) {
	var p respBody
	request, err := newfileUploadRequest(host, csr)
	if err != nil {
		return &p, err
	}

	// Get the SystemCertPool, continue with an empty pool on error
	clientCertPool := x509.NewCertPool()
	clientCACert, err := ioutil.ReadFile(m)
	if err != nil {
		return &p, err
	}

	clientCertPool.AppendCertsFromPEM(clientCACert)
	config := &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            clientCertPool,
	}
	config.BuildNameToCertificate()
	tr := &http.Transport{TLSClientConfig: config}
	client := &http.Client{
		Transport: tr,
		Timeout:   1500 * time.Millisecond,
	}
	//** end of clean up
	resp, err := client.Do(request)
	if err != nil {
		return &p, err
	}
	body := &bytes.Buffer{}
	_, err = body.ReadFrom(resp.Body)
	if err != nil {
		return &p, err
	}
	resp.Body.Close()
	b := body.Bytes()
	if resp.StatusCode != 200 {
		return &p, errors.New(body.String())
	}
	err = json.Unmarshal(b, &p)
	if err != nil {
		return &p, err
	}
	return &p, nil
}
