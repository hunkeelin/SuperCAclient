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
	for _, c := range crt {
		pem.Encode(clientCRTFile, &pem.Block{Type: "CERTIFICATE", Bytes: c})
		//if i == 0 {
		//	pem.Encode(clientCRTFile, &pem.Block{Type: "CERTIFICATE", Bytes: c})
		//} else {
		//	clientCRTFile.Write(c)
		//}
	}
	clientCRTFile.Close()

	keyOut, err := os.OpenFile(w.Path+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: key})
	keyOut.Close()
	return nil
}
func Writecrtkey(w WriteInfo) error {
	csr, key := klinpki.GenCSRv2(w.CSRConfig)

	masteraddr := klinutils.GetHostnameFromCert(w.CA)
	f, err := Getcrtv2(w.CA, masteraddr, w.CAport, csr.Bytes)
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
