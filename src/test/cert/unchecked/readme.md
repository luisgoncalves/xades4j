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

Bad certificate expired validation date.

```
certtool --outder --outfile expired.key --generate-privkey
certtool --outder --outfile expired.cer --generate-certificate --inder --load-ca-certificate TestCA.cer --load-ca-privkey TestCA.key --load-privkey expired.key --template expired.template
```

Bad certificate not yet valid validation date.

```
certtool --outder --outfile notYetValid.key --generate-privkey
certtool --outder --outfile notYetValid.cer --generate-certificate --inder --load-ca-certificate TestCA.cer --load-ca-privkey TestCA.key --load-privkey notYetValid.key --template notYetValid.template
```

## Create PKCS#12 keystores used for signing

These are needed for all end entity certificates.

```
certtool -i --inder --infile good.cer --outfile good.pem
certtool --outder --outfile=good.p12 --to-p12 --password=password --p12-name=good --inder --load-privkey=good.key --load-certificate=good.pem --load-ca-certificate=TestCA.cer
```

```
certtool -i --inder --infile noSignKeyUsage.cer --outfile noSignKeyUsage.pem
certtool --outder --outfile=noSignKeyUsage.p12 --to-p12 --password=password --p12-name=noSignKeyUsage --inder --load-privkey=noSignKeyUsage.key --load-certificate=noSignKeyUsage.pem --load-ca-certificate=TestCA.cer
```

```
certtool -i --inder --infile expired.cer --outfile expired.pem
certtool --outder --outfile=expired.p12 --to-p12 --password=password --p12-name=expired --inder --load-privkey=expired.key --load-certificate=expired.pem --load-ca-certificate=TestCA.cer
```

```
certtool -i --inder --infile notYetValid.cer --outfile notYetValid.pem
certtool --outder --outfile=notYetValid.p12 --to-p12 --password=password --p12-name=notYetValid --inder --load-privkey=notYetValid.key --load-certificate=notYetValid.pem --load-ca-certificate=TestCA.cer
```