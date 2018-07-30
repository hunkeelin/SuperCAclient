package client
import (
    "testing"
    "fmt"
    "github.com/hunkeelin/pki"
)

func TestOut(t *testing.T){
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
    writecrtkey("diu","rootca.crt","2018",false,j)
}
