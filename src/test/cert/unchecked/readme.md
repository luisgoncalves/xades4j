# Certificate for keyUsage verification testing

Test keys and certificates are generated using GnuTLS certtool. The
`.template` files in this directory define the certificate properties
including keyUsage. The TestCA directly signs end entity certificates.

## Generating keys and certificates

The test root CA.

```
certtool --outder --outfile TestCA.key --generate-privkey
certtool --outder --outfile TestCA.cer --generate-self-signed --inder --load-privkey TestCA.key --template TestCA.template
```

Good certificate with "digitalSignature" keyUsage.

```
certtool --outder --outfile good.key --generate-privkey
certtool --outder --outfile good.cer --generate-certificate --inder --load-ca-certificate TestCA.cer --load-ca-privkey TestCA.key --load-privkey good.key --template good.template
```

Bad certificate with "dataEncipherment" keyUsage, which is not allowed
to sign.

```
certtool --outder --outfile noSignKeyUsage.key --generate-privkey
certtool --outder --outfile noSignKeyUsage.cer --generate-certificate --inder --load-ca-certificate TestCA.cer --load-ca-privkey TestCA.key --load-privkey noSignKeyUsage.key --template noSignKeyUsage.template
```

## Create PKCS#12 keystores used for signing

These are needed for both end entity certificates.

```
certtool -i --inder --infile good.cer --outfile good.pem
certtool --outder --outfile=good.p12 --to-p12 --password=password --p12-name=good --inder --load-privkey=good.key --load-certificate=good.pem --load-ca-certificate=TestCA.cer
```

```
certtool -i --inder --infile noSignKeyUsage.cer --outfile noSignKeyUsage.pem
certtool --outder --outfile=noSignKeyUsage.p12 --to-p12 --password=password --p12-name=good --inder --load-privkey=noSignKeyUsage.key --load-certificate=noSignKeyUsage.pem --load-ca-certificate=TestCA.cer
```
