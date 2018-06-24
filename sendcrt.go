package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

// Creates a new file upload http request with optional extra params
func newfileUploadRequest(uri string, csr []byte) (*http.Request, error) {
	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(csr))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, err
}

func getcrt(m, host string, csr []byte) ([]byte, error) {
	var toReturn []byte
	request, err := newfileUploadRequest(host, csr)
	if err != nil {
		return toReturn, err
	}

	// Get the SystemCertPool, continue with an empty pool on error
	clientCertPool := x509.NewCertPool()
	clientCACert, err := ioutil.ReadFile(m)
	if err != nil {
		log.Fatal("Unable to open cert", err)
	}

	clientCertPool.AppendCertsFromPEM(clientCACert)
	config := &tls.Config{
		InsecureSkipVerify: false,
		//	RootCAs:            clientCertPool,
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
		return toReturn, err
	}
	body := &bytes.Buffer{}
	_, err = body.ReadFrom(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	resp.Body.Close()
	toReturn = body.Bytes()
	if resp.StatusCode != 200 {
		return toReturn, errors.New(body.String())
	}
	return toReturn, nil
}
