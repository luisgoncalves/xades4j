package xades4j.production;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERUTF8String;


import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;

import org.bouncycastle.asn1.x500.style.RFC4519Style;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.properties.DataObjectDesc;

import xades4j.providers.impl.DirectKeyingDataProvider;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Random;


/**
 * @author Artem R. Romanenko
 * @version 02/04/2018
 */
@RunWith(Parameterized.class)
public class SignerSpecificTest extends SignerTestBase {
    private static final String NATIONAL_ORGANIZATION_NAME_CYRILLIC = "National organization name '\u043F\u0440\u0438\u043C\u0435\u0440'";
    private static final String NATIONAL_ORGANIZATION_NAME_ARABIC = "National organization name '\u0645\u062B\u0627\u0644'";

    @Parameterized.Parameters
    public static Collection<ASN1Encodable[]> data() {
        ArrayList<ASN1Encodable[]> result = new ArrayList<ASN1Encodable[]>();
        result.add(new ASN1Encodable[]{new DERBMPString(NATIONAL_ORGANIZATION_NAME_CYRILLIC)});
        result.add(new ASN1Encodable[]{new DERUTF8String(NATIONAL_ORGANIZATION_NAME_CYRILLIC)});
        result.add(new ASN1Encodable[]{new DERBMPString(NATIONAL_ORGANIZATION_NAME_ARABIC)});
        result.add(new ASN1Encodable[]{new DERUTF8String(NATIONAL_ORGANIZATION_NAME_ARABIC)});
        return result;
    }

    @Parameterized.Parameter
    public ASN1Encodable commonName;

    @Test
    public void signWithNationalCertificate() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyGen.initialize(1024, new SecureRandom());
        Date validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        long add = (1L * 365L * 24L * 60L * 60L * 1000L);  //1 year
        Date validityEndDate = new Date(System.currentTimeMillis() + add);
        KeyPair rootCAKeyPair = keyGen.generateKeyPair();
        KeyPair mainKeyPair = keyGen.generateKeyPair();

        X509Certificate certCA;
        {
            //generate certificate with national symbols in DN
            X500NameBuilder x500NameBuilder = new X500NameBuilder();
            AttributeTypeAndValue attr = new AttributeTypeAndValue(RFC4519Style.cn, commonName);
            x500NameBuilder.addRDN(attr);
            X500Name caName = x500NameBuilder.build();
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    caName, // issuer authority
                    BigInteger.valueOf(new Random().nextInt()), //serial number of certificate
                    validityBeginDate, // start of validity
                    validityEndDate, //end of certificate validity
                    caName, // subject name of certificate
                    rootCAKeyPair.getPublic()); // public key of certificate
            // key usage restrictions
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign
                    | KeyUsage.digitalSignature | KeyUsage.keyEncipherment
                    | KeyUsage.dataEncipherment | KeyUsage.cRLSign));
            builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(true));
            certCA = new JcaX509CertificateConverter().getCertificate(builder
                    .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).
                            build(rootCAKeyPair.getPrivate())));
        }

        X509Certificate certRsaSha1;
        {
            //without national symbols, see using org.apache.xml.security.keys.content.X509Data#addSubjectName(java.security.cert.X509Certificate) in xades4j.production.KeyInfoBuilder#buildKeyInfo()
            String subject = "CN=test user";
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    certCA, // issuer authority
                    BigInteger.valueOf(new Random().nextInt()), //serial number of certificate
                    validityBeginDate, // start of validity
                    validityEndDate, //end of certificate validity
                    new X500Name(subject), // subject name of certificate
                    mainKeyPair.getPublic()); // public key of certificate
            // key usage restrictions
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign
                    | KeyUsage.digitalSignature | KeyUsage.keyEncipherment
                    | KeyUsage.dataEncipherment | KeyUsage.cRLSign));

            builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(true));
            certRsaSha1 = new JcaX509CertificateConverter().getCertificate(builder
                    .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).
                            build(rootCAKeyPair.getPrivate())));
        }

        XadesSigner signer = new XadesBesSigningProfile(new DirectKeyingDataProvider(certRsaSha1, mainKeyPair.getPrivate())).newSigner();
        Document doc1 = getTestDocument();
        Element elemToSign = doc1.getDocumentElement();
        DataObjectDesc obj1 = new DataObjectReference('#' + elemToSign.getAttribute("Id")).withTransform(new EnvelopedSignatureTransform());
        SignedDataObjects signDataObject = new SignedDataObjects(obj1);
        signer.sign(signDataObject, doc1.getDocumentElement());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        outputDOM(doc1, baos);
        //expected without parsing exception
        Document doc = parseDocument(new ByteArrayInputStream(baos.toByteArray()));

    }

}