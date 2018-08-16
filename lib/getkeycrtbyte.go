package client

import (
	"bytes"
	"encoding/pem"
	"errors"
	"github.com/hunkeelin/klinutils"
	"github.com/hunkeelin/pki"
)

func Getkeycrtbyte(w WriteInfo) (crtpem, keypem []byte, err error) {
	var crt [][]byte
	var bcrt, bkey bytes.Buffer
	csr, key := klinpki.GenCSRv2(w.CSRConfig)
	if w.CA == "" && len(CABytes) == 0 {
		return bcrt.Bytes(), bkey.Bytes(), errors.New("Please specify CA in bytes or give the location of the CA")
	}
	g := GetCrtInfo{
		Ca:      w.CA,
		Port:    w.CAport,
		Csr:     csr.Bytes,
		CaBytes: w.CABytes,
	}
	if w.CA != "" {
		masteraddr, err := klinutils.GetHostnameFromCertv2(w.CA)
		if err != nil {
			return bcrt.Bytes(), bkey.Bytes(), err
		}
		g.Host = masteraddr
	} else {
		if w.CAName == "" {
			return bcrt.Bytes(), bkey.Bytes(), errors.New("Please specify name of the CA")
		}
		g.Host = w.CAName
	}
	f, err := Getcrtv2(g)
	if err != nil {
		return bcrt.Bytes(), bkey.Bytes(), err
	}
	crt = append(crt, f.Cert)
	if w.Chain {
		p, rest := pem.Decode(f.ChainOfTrust)
		crt = append(crt, p.Bytes)
		for len(rest) != 0 {
			p, rest = pem.Decode(rest)
			crt = append(crt, p.Bytes)
		}
	}
	for _, c := range crt {
		pem.Encode(&bcrt, &pem.Block{Type: "CERTIFICATE", Bytes: c})
	}
	pem.Encode(&bkey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: key.Bytes})
	return bcrt.Bytes(), bkey.Bytes(), nil
}
