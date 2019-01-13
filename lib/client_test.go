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
		EmailAddress:       "support@abc.com",
		RsaBits:            2048,
		Country:            "USA",
		Province:           "SHIT",
		Locality:           "NOOB",
		OrganizationalUnit: "IT",
		Organization:       "abc",
	}
	w := WriteInfo{
		CA:        "rootca.crt",
		CAport:    klinutils.Stringtoport("superca"),
		CAName:    "util3.klin-pro.com",
		Chain:     false,
		CSRConfig: j,
		Path:      "diui",
		//		SignCA:    "noob",
	}
	c, k, err := Getkeycrtbyte(w)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(c))
	fmt.Println(string(k))
}
