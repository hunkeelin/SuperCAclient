package client

import (
	"fmt"
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
		CAport:    "2018",
		Chain:     true,
		CSRConfig: j,
		Path:      "diui",
	}
	err := Writecrtkeyv2(w)
	if err != nil {
		panic(err)
	}
}
