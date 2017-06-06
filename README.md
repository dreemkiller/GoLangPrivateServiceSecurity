# GoLangPrivateServiceSecurity
GoLang: Using certificates and keys to secure private services

Problem statement: I've got multiple services that communicate on AWS via a private subnet. However, I'd like a couple of additional layers of security. Each service initiating a request should check the public key returned by the hosting service and ensure it's a specific value (the "pinned" public key value), and each hosting service should require each request to contain a client certificate that matches what is expected and that each request be signed by the corresponding private key.

Why can't we just use standard Public Key Infrastructure (X.509 certificates signed by Certificate Authorities) instead of "pinning" the public key? There's a couple of reasons. First, public CA's (rightly) won't create a certificate for a private IP address. Also, since we are deploying via AWS, the IP address of a service will change on each deployment.

Why aren't we creating our own private CA? Partially because it's a bit of a pain to manage it, and also because certificate revocation using a CA is cumbersome and error-prone.

So here's the first code snippet. It returns a "Dialer" function that should be used as the DialTLS member of the http.Transport struct on the client.

```go
package TLSDialer;

import (
    "crypto/tls"
    "crypto/sha256"
    "crypto/x509"
    "io/ioutil"
    "fmt"
    "bytes"
    "net"
    
    "github.com/pkg/errors"
)

// Dialer is the function to be used as the DialTLS member of the http.Transport struct.
type Dialer func(network, addr string) (net.Conn, error)

// MakeDialer takes as input the SHA256 hash of the public key to be pinned and a path to a client certificate file and a path to the associated key file.
// It returns a Dialer function that should be used as the DialTLS member of the http.Transport struct. The returned function will send the client certificate, and 
// check the public keys returned by the host on the other end of the connection and compare their 
// sha256 hash against sha256Fingerprint. If one of them matches, it allows the connection to continue
// (by returning a valid net.Conn instance). If none of them matches, it generates an error, which prevents
// the connection from continuing.
func MakeDialer(pubKeyFingerprint []byte, certFilename string, keyFilename string) (dialer Dialer, err error) {

    // Before we create and return the closure function, set up the tlsConfig with the client certificate
    var tlsConfig tls.Config
    tlsConfig.InsecureSkipVerify = true
    var clientCert tls.Certificate
    clientCert, err = tls.LoadX509KeyPair(certFilename, keyFilename); if err != nil {
        err = errors.Wrap(err, "Failed to load client certificate and key")
        return
    }

    var clientCertPem []byte
    clientCertPem, err = ioutil.ReadFile(certFilename); if err != nil {
      err = errors.Wrap(err, "Failed to read client certificate pem file")
      return
    }

    clientCertPool := x509.NewCertPool()
    clientCertPool.AppendCertsFromPEM(clientCertPem)

    tlsConfig.Certificates =  []tls.Certificate{clientCert}
    tlsConfig.RootCAs = clientCertPool
    tlsConfig.BuildNameToCertificate()

    // create the closure function, using the above tlsConfig for the connection
    dialer =  func(network, addr string) (netConn net.Conn, err error) {
        var tlsConn *tls.Conn

        tlsConn, err = tls.Dial(network, addr, &tlsConfig); if err != nil {
            err = errors.Wrap(err, "Failed to create TLS Dialer")
            return
        }
        connectionState := tlsConn.ConnectionState()
        pinnedKeyValid := false
        for _, peerCertificate := range connectionState.PeerCertificates {
            var der []byte
            der, err = x509.MarshalPKIXPublicKey(peerCertificate.PublicKey); if err != nil {
                err = errors.Wrap(err, "Failed to Marshal Public Key")
                return
            }
            hash := sha256.Sum256(der)

            if bytes.Compare(hash[0:], pubKeyFingerprint) == 0 {
                pinnedKeyValid = true
                break;
            }
        }
        if !pinnedKeyValid {
            err = fmt.Errorf("Did not find the pinned key.")
            return
        }
        netConn = tlsConn
        return
    }
    return
}
```
Now, when the client makes a request, it does the following:
```go
  dialer, err := TLSDialer.MakeDialer(pubKeyHash[:], clientCertificatePath, clientKeyPath);
  
  client := &http.Client{
      Transport: &http.Client{
          DialTLS: dialer,
      },
  }
  request, err := http.NewRequest("POST", serviceURL, payload);
  
  response, err := client.Do(request);
```
There are a couple of things to note here. First, the clientCertificatePath should be a path to a file containing a self-signed certificate, and the clientKeyPath should be a path to a file containing a private RSA, ECC, or DH key. You can generate these as follows:
```bash
openssl genrsa -out client.key 4096
```
which generates a 4k RSA private key and places it in client.key.
```bash
openssl req -new -x509 -sha256 -key client.key -out client.crt -days 3650
```
It will prompt you for some information to be included in the certificate. What you enter really doesn't matter for our use-case, but entering useful information will make it easier to manage certificates. It generates a self-signed x.509 certificate that is valid for ten years, and places it in the file client.crt.

The pubKeyHash value should be the SHA256 hash of the public key being used by the service you are communicating with. if you've got the PEM encoded public key for the service in a file, you can generate it this way:
```bash
openssl rsa -in servicekey.pem -pubout > servicepubkey.pem | openssl dgst -sha256
```
Only the data to the right of the equal sign should be included in the pubKeyHash byte array.

Here's a code snippet for the server side:
```go
    clientCert, err := ioutil.ReadFile(clientCertificatePath); if err != nil {
        err = errors.Wrap(err, "Failed to read client certificate file")
        return
    }

    clientCertPool := x509.NewCertPool()
    clientCertPool.AppendCertsFromPEM(clientCert)

    http.Handle("/", myHttpHandler)


    server := &http.Server {
        ServerURL: ":" + portNum,
        TLSConfig: &tls.Config {
            ClientAuth: tls.RequireAndVerifyClientCert,
            ClientCAs: clientCertPool,
        },
    }
    err = server.ListenAndServeTLS(serverCertificatePath, serverKeyPath); if err != nil {
        RLLogger.Error.Printf("Failed to start server:" + err.Error())
    }
```
The clientCertificatePath should be a path to a copy of the certificate generated previous, client.crt.
The serverKeyPath is a path to the RSA private key used by the server.
The serverCertificatePath is a path to the self-signed certitifcate for the server, signed by the RSA private key.

Now, when the client connects to the server, it checks the public key it received, and verifies that it's correct. The client also sends a client certificate with the request, which is authenticated by the server.

