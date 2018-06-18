package main

import (
	"encoding/pem"
	"flag"
	"github.com/hunkeelin/pki"
	"log"
	"os"
)

var (
	outdir       = flag.String("Outdir", "./", "location of the output e.g /tmp or $pwd (default: currentd directory")
	ca           = flag.String("ca", "", "location of the CA crt/pem")
	caport       = flag.String("CAport", "2018", "the port of the CA is listening for this software")
	rsaBits      = flag.Int("RsaBits", 2048, "RSA bits")
	country      = flag.String("Country", "USA", "Specify Country")
	state        = flag.String("State", "CA", "Specify state")
	city         = flag.String("City", "San Francisco", "Specify City")
	orgu         = flag.String("OrganizationUnit", "IT", "Specify Organization Unit")
	org          = flag.String("Organization", "SQ", "Specify Organization")
	emailAddress = flag.String("EmailAddress", "support@abc.com", "email address")
	outname      = flag.String("outname", "", "Output file name")
	h            string
)

func main() {
	flag.Parse()
	if *outname == "" {
		h = klinpki.Hostname()
	} else {
		h = *outname
	}
	if *ca == "" {
		log.Fatal("please specify location of ca. Eg, -ca /tmp/master.pem")
	}
	if *outdir == "" {
		log.Fatal("please specify location of output e.g -outdir /tmp/")
	}
	odir := *outdir
	if string(odir[len(odir)-1]) != "/" {
		odir += "/"
	}
	j := &klinpki.CSRConfig{
		EmailAddress:       *emailAddress,
		RsaBits:            *rsaBits,
		Country:            *country,
		Province:           *state,
		Locality:           *city,
		OrganizationalUnit: *orgu,
		Organization:       *org,
	}
	csr, key := klinpki.GenCSRv2(j)

	// write keyfile
	keyOut, err := os.OpenFile(odir+h+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	pem.Encode(keyOut, key)
	keyOut.Close()

	masteraddr := getHostnameFromCert(*ca)
	url := "https://" + masteraddr + ":" + *caport
	f, err := getcrt(*ca, url, csr.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	clientCRTFile, err := os.Create(odir + h + ".crt")
	if err != nil {
		panic(err)
	}
	pem.Encode(clientCRTFile, &pem.Block{Type: "CERTIFICATE", Bytes: f})
	clientCRTFile.Close()
}
