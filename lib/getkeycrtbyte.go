package client

import (
	"encoding/pem"
	"github.com/hunkeelin/klinutils"
	"github.com/hunkeelin/pki"
)

func Getkeycrtbyte(w WriteInfo) (crtpem [][]byte, keypem []byte, err error) {
	var crt [][]byte
	csr, key := klinpki.GenCSRv2(w.CSRConfig)

	masteraddr := klinutils.GetHostnameFromCert(w.CA)
	f, err := Getcrtv2(w.CA, masteraddr, w.CAport, csr.Bytes)
	if err != nil {
		return crt, key.Bytes, err
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
	return crt, key.Bytes, nil
}
