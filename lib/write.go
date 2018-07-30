package client

import (
    "os"
    "encoding/pem"
    "github.com/hunkeelin/pki"
    "github.com/hunkeelin/klinutils"
)

func writecrtkey(p,ca,caport string,withchain bool,j *klinpki.CSRConfig){
    csr, key := klinpki.GenCSRv2(j)

    masteraddr := klinutils.GetHostnameFromCert(ca)
    f, err := Getcrtv2(ca, masteraddr,caport, csr.Bytes)
    if err != nil {
        panic(err)
    }
    //clientCRTFile, err := os.Create(odir + h + ".crt")
    clientCRTFile, err := os.OpenFile(p+".crt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0644)
    if err != nil {
        panic(err)
    }
    pem.Encode(clientCRTFile, &pem.Block{Type: "CERTIFICATE", Bytes: f.Cert})
    if withchain {
        clientCRTFile.Write(f.ChainOfTrust)
    }
    clientCRTFile.Close()
    keyOut, err := os.OpenFile(p+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
    if err != nil {
        panic(err)
    }
    pem.Encode(keyOut, key)
    keyOut.Close()
}
