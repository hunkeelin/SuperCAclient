package client

import (
	"encoding/pem"
	"github.com/hunkeelin/klinutils"
	"github.com/hunkeelin/pki"
	"os"
)

func Writecrtkeyv2(w WriteInfo) error {
	crt, key, err := Getkeycrtbyte(w)
	if err != nil {
		return err
	}
	clientCRTFile, err := os.OpenFile(w.Path+".crt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	clientCRTFile.Write(crt)
	clientCRTFile.Close()

	clientKeyFile, err := os.OpenFile(w.Path+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	clientKeyFile.Write(key)
	clientKeyFile.Close()

	//	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: key})
	return nil
}
func Writecrtkey(w WriteInfo) error {
	csr, key := klinpki.GenCSRv2(w.CSRConfig)

	masteraddr, err := klinutils.GetHostnameFromCertv2(w.CA)
	if err != nil {
		return err
	}
	g := GetCrtInfo{
		CA:      w.CA,
		Host:    masteraddr,
		Port:    w.CAport,
		Csr:     csr.Bytes,
		CABytes: w.CABytes,
	}
	f, err := Getcrtv2(g)
	if err != nil {
		return err
	}
	//clientCRTFile, err := os.Create(odir + h + ".crt")
	clientCRTFile, err := os.OpenFile(w.Path+".crt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	pem.Encode(clientCRTFile, &pem.Block{Type: "CERTIFICATE", Bytes: f.Cert})
	if w.Chain {
		clientCRTFile.Write(f.ChainOfTrust)
	}
	clientCRTFile.Close()
	keyOut, err := os.OpenFile(w.Path+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, key)
	keyOut.Close()
	return nil
}
