package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
)

func getHostnameFromCert(path string) string {
	e, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("can't read file")
	}
	block, _ := pem.Decode(e)
	if block == nil {
		log.Fatal("fail to parse certifiate pem.")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("can't parse file", path)
		log.Fatal(err)
	}
	return leaf.DNSNames[0]
}
