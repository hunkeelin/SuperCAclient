package client

import (
    "os"
    "encoding/pem"
    "github.com/hunkeelin/pki"
    "github.com/hunkeelin/klinutils"
)
func Writecrtkey(w WriteInfo) error{
    csr, key := klinpki.GenCSRv2(w.CSRConfig)

    masteraddr := klinutils.GetHostnameFromCert(w.CA)
    f, err := Getcrtv2(w.CA, masteraddr,w.CAport, csr.Bytes)
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
