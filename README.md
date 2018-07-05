## Introduction ##
This is the go version of a CAclient. The CAclient will send csr to the CA server. Base on the configuration of the CA server, the client might get back a certificate


#### Installation ####
I've included the binary for linux. However, if you want to compile your own:
1. Download and install the latest version of `go`
2. Run build.sh

### Usage ###
```
./calient -h // for help
```
- For security purpose, the client determines the destination of the CA not by manual hostname arguements or config but from the `rootca` it trust. 
```
wget https://SuperCAServer:$port/cacert/rootca.crt
./caclient -ca rootca.crt
```
- One thing that needs to take caution is the `chain`. That option will include the chain of trust in your output certificate. This option is critical for your mtls application. let's assume the mtls.crt is a ca cert, it was signed by `intermca` and `intermca` is signed by `rootca`. You want your application to trust anything that is signed by intermca and rootca. When you generate your crt and key via SuperCAClient, you would want to include the `chain` option. 

- Another example, let's assume the mtls.crt is a ca cert, it was signed by `intermca` and `intermca` is signed by `rootca`. If you want your mtls server to only trust certs signed by `mtls.crt` and not any other certi. Then when you download mtls.crt to trust in your application, you would want to remove the latter parts of the certifciate in the file; and opt out of the `chain` option in your client side since it's unneccesary.

### Notes ###
- For any questions and feature request ping me in reddit 
