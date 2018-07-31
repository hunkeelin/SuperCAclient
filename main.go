package main

import (
	"flag"
	"github.com/hunkeelin/SuperCAClient/lib"
	"github.com/hunkeelin/pki"
	"log"
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
	chain        = flag.Bool("chain", false, "include chain of trust")
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
	w := client.WriteInfo{
		CA:     *ca,
		CAport: *caport,
		Chain:  *chain,
		CSRConfig: &klinpki.CSRConfig{
			EmailAddress:       *emailAddress,
			RsaBits:            *rsaBits,
			Country:            *country,
			Province:           *state,
			Locality:           *city,
			OrganizationalUnit: *orgu,
			Organization:       *org,
		},
		Path: odir + h,
	}
	err := client.Writecrtkeyv2(w)
	if err != nil {
		panic(err)
	}
}
