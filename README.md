# Lorica

Lorica provides tools for operating a certification authority (CA) that
leverages PKCS #11 cryptographic tokens.

## PKCS #11 cryptographic tokens

By design, Lorica does not get hold of the private key. Instead, it asks
another device, usually a hardware security module (HSM), to perform the
cryptographic functions on its behalf.

Such devices, commonly known as cryptographic tokens, are purpose-built
to generate cryptographic keys and sign information without revealing
the private key. This greatly reduces the risk of key compromise, one of
the main risks certification authorities defend against.

Lorica interacts with cryptographic tokens using the Cryptoki API, as
specified by the [PKCS #11] standard.

### SoftHSM2

[SoftHSM2] is a software implementation of a generic cryptographic token
with a PKCS #11 interface.

SoftHSM2 is required for running the test suite. The user running the
test suite should have access to `softhsm2-util` command and the PKCS#11
module should be available at `/usr/lib/softhsm/libsofthsm2.so`.

## Quickstart

In this tutorial, we will use the `lorica` command-line tool with a
SoftHSM2 token to deploy a two-tier PKI.

### Prepare the cryptographic token

Lorica loads PKCS #11 token configurations from environment variables,
you can also use a `.env` file like this:

```
LORICA_TOKEN_MODULE="/usr/lib/softhsm/libsofthsm2.so"
LORICA_TOKEN_LABEL=lorica_demo
LORICA_TOKEN_PIN=123456
```

The token must be initialized before use. For SoftHSM2, you can do it by
using this command:

```sh
$ softhsm2-util --init-token --free --label lorica_demo --pin 123456 --so-pin lorica
```

You can do a quick smoke test with the `lorica info` command:

```sh
$ lorica info
Token label:    lorica_demo
Manufacturer:   SoftHSM project
Token model:    SoftHSM v2
Serial number:  4788d9b901eef752
```

### Set up the Root CA

First we need to prepare a configuration file in JSON format, like this:

```json
{
  "CN": "Pied Piper Root CA",
  "name": {
    "OU": "Certification Authority",
    "O": "Pied Piper",
    "L": "Silicon Valley",
    "ST": "CA",
    "C": "US"
  },
  "key": {
    "algo": "rsa",
    "size": 4096
  },
  "self_sign": true,
  "expiry": "87600h",
  "ca_constraint": {
    "is_ca": true
  }
}
```

Then we use the `lorica init` command to set up the Root CA:

```sh
$ lorica init root_ca.json -f root.ca
```

This will create a new file, `root.ca`, which keeps the internal state.
Just specify this file when running a command and Lorica will know which
CA you are working with. For example, to view the certificate of Root
CA:

```sh
$ lorica cert -f root.ca | openssl x509 -noout -text
```

### Set up the Subordinate CA

Similarly, prepare a configuration for the Subordinate CA. Not that we
have `self_sign` set to false:

```json
{
  "CN": "Pied Piper Subordinate CA",
  "name": {
    "OU": "Certification Authority",
    "O": "Pied Piper",
    "L": "Silicon Valley",
    "ST": "CA",
    "C": "US"
  },
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "self_sign": false,
  "usages":  [
    "signing",
    "key encipherment",
    "server auth",
    "client auth"
  ],
  "expiry": "8760h",
  "ca_constraint": {
    "is_ca": false
  }
}
```

Use the same `lorica init` command to set up the Subordinate CA. Only
this time, we need to export the CSR.

```sh
$ lorica init sub_ca.json -f sub.ca --export-csr sub_ca.csr
```

After that, ask the Root CA to sign the CSR of the Subordinate CA and
import the newly-issued certificate to the Subordinate CA:

```sh
$ lorica issue -f root.ca sub_ca.csr --export-cert sub_ca.crt
$ lorica cert -f sub.ca --import sub_ca.crt
```

The Subordinate CA is now fully operational.

### Issue a end-entity certificate

Create a CSR for the end-entity:

```sh
$ openssl req -nodes -newkey rsa:2048 -sha256 \
  -subj /CN=piedpiper.example.com \
  -keyout piedpiper.example.com.key \
  -out piedpiper.example.com.csr
```

Ask Subordinate CA to sign the CSR and export the issued certificate:

```sh
$ lorica issue -f sub.ca piedpiper.example.com.csr --export-cert piedpiper.example.com.crt
```

### Revoke a certificate

To revoke a certificate, pass its serial number to the `lorica revoke`
command:

```sh
$ lorica revoke -f sub.ca 154650704943387378214337212672624373342364461517
```

After that, update the certificate revocation list:

```sh
$ lorica crl -f sub.ca sub_ca.crl
```

Inpsect the CRL to confirm the certificate is now being revoked:

```sh
$ openssl crl -inform DER -text -noout -in sub_ca.crl
```

[PKCS #11]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html
[SoftHSM2]: https://github.com/opendnssec/SoftHSMv2
