package client

import (
	"fmt"
	"github.com/hunkeelin/klinutils"
	"github.com/hunkeelin/pki"
	"testing"
)

func TestOut(t *testing.T) {
	fmt.Println("testing Out")
	j := &klinpki.CSRConfig{
		EmailAddress:       "support@varomoney.com",
		RsaBits:            2048,
		Country:            "USA",
		Locality:           "SF",
		OrganizationalUnit: "IT",
		Organization:       "VARO",
		DNSNames:           []string{"6F11ABD8D1207DACC2357D2DBF6F222.yl4.us-west-2.eks.amazonaws.com"},
	}
	w := WriteInfo{
		CA:        "rootca.crt",
		CAport:    klinutils.Stringtoport("superca"),
		CAName:    "util3.klin-pro.com",
		Chain:     false,
		CSRConfig: j,
		SignCA:    "intermca",
	}
	c, k, err := Getkeycrtbyte(w)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(c))
	fmt.Println(string(k))
}
