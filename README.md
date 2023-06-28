# PKCS11Key

The pkcs11key package implements a crypto.Signer interface for a PKCS#11 private key.

If you are using Go modules, you should import this with the module-compatible
path `github.com/letsencrypt/pkcs11key/v4`.

# Testing

* You will need to install SoftHSMv2.
* Run `./test.sh`
* If you need to regenerate key material, run the following and check the new files back into git.
```
cd v4/testdata
openssl ecparam -name prime256v1 -genkey | openssl pkcs8 -topk8 -nocrypt > entropic_ecdsa.key
openssl req -new -x509 -key entropic_ecdsa.key -out entropic_ecdsa.pem -days 1000 -subj /CN=entropic\ ECDSA
openssl req -new -newkey rsa:2048 -nodes -x509 -keyout silly_signer.key -out silly_signer.pem -days 1000 -subj /CN=silly\ signer
cd -
```

# License Summary
Some of this code is Copyright (c) 2014 CloudFlare Inc., some is Copyright (c)
2015 [Internet Security Research Group](https://www.abetterinternet.org/).

The code is licensed under the BSD 2-clause license. See the [LICENSE](./LICENSE) file for more details.
