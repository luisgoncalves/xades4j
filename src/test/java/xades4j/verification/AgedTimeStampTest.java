/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Hubert Kario - QBS.
 *
 * XAdES4j is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or any later version.
 *
 * XAdES4j is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with XAdES4j. If not, see <http://www.gnu.org/licenses/>.
 */
package xades4j.verification;

import static org.junit.Assert.assertEquals;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.utils.Constants;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.util.Store;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import xades4j.XAdES4jException;
import xades4j.production.Enveloped;
import xades4j.production.XadesFormatExtenderProfile;
import xades4j.production.XadesSignatureFormatExtender;
import xades4j.production.XadesSigningProfile;
import xades4j.production.XadesTSigningProfile;
import xades4j.providers.CannotBuildCertificationPathException;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.TSACertificateValidationProvider;
import xades4j.providers.impl.DirectKeyingDataProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.providers.impl.PKIXTSACertificateValidationProvider;
import xades4j.utils.DOMHelper;
import xades4j.utils.XadesProfileResolutionException;
import xades4j.verification.FullCert.CRLEntries;

/**
 * Extensive tests of signer and verifiers with special emphasis on testing time stamp
 * related corner cases.
 *
 * @author Hubert Kario
 *
 */
public class AgedTimeStampTest
{
    private static final CertStore emptyCertStore;
    /*
     * first test uses only XAdES-T signatures, Signature is from one CA and TimeStamp is
     * signed by TSA from another CA, CRLs are generated on demand in tests
     */
    private static FullCert test01_T_userCaCert;
    private static FullCert test01_T_tsaCaCert;
    private static FullCert test01_T_userCert;
    private static FullCert test01_T_tsaCert;
    private static X509CRL  test01_T_tsaCRL_1;
    private static X509CRL  test01_T_userCRL_2;
    private static X509CRL  test01_T_tsaCRL_2;
    private static Store    test01_T_userCaStore;
    private static KeyStore test01_T_userTrustAnchors;
    private static KeyStore test01_T_tsaTrustAnchors;

    /**
     * cryptographic data for signature creation
     */
    private static KeyingDataProvider test01_keyingDataProviderNow;
    /**
     * cryptographic data from 30min ago for validation of certificates
     */
    private static CertificateValidationProvider test01_userCertValidationDataProviderPast30m;
    /**
     * validation data provider that has revocation information from TSA from 30min ago
     */
    private static TSACertificateValidationProvider test01_tsaValidationDataProviderPast30m;
    /**
     * validation data provider that has current revocation information
     */
    private static CertificateValidationProvider test01_userCertValidationDataProviderNow;
    /**
     * validation data provider that has current revocation information for TSA
     */
    private static TSACertificateValidationProvider test01_tsaValidationDataProviderNow;

    /*
     * data for XAdES-X (SigAndRefsTimeStamp) tests
     */
    private static FullCert test02_X_userCaCert;
    private static FullCert test02_X_userCert;
    private static FullCert test02_X_tsaCaCert;
    private static FullCert test02_X_tsa1Cert;
    private static FullCert test02_X_tsa2Cert;
    private static X509CRL  test02_X_tsaCRL_1;
    private static X509CRL  test02_X_tsaCRL_2;
    //private static X509CRL  test02_X_tsaCRL_3;
    private static Store    test02_X_userCaStore;
    private static KeyStore test02_X_userTrustAnchors;
    private static KeyStore test02_X_tsaTrustAnchors;

    private static KeyingDataProvider test02_keyingDataproviderNow;
    private static CertificateValidationProvider test02_userCertValidationDataProviderXCreation;
    private static TSACertificateValidationProvider test02_tsaCertValidationDataProviderXCreation;
    private static TSACertificateValidationProvider test02_tsaCertValidationDataProviderNow;
    private static CertificateValidationProvider test02_userCertMinimalValidationDataProvider;
    private static TSACertificateValidationProvider test02_tsaCertMinimalValidationDataProvider;

    private static final long ONE_HOUR_IN_MS = 60 * 60 * 1000;
    static
    {
        try {

        Date now = new Date();
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        System.out.println("AgedTimeStampTest start, current time is " + now);

        CertStoreParameters emptyParams = new CollectionCertStoreParameters();
        emptyCertStore = CertStore.getInstance("Collection", emptyParams );

        /* ******************************************************************************
         *
         * Create cryptographic data for XAdES-T tests
         *
         * *****************************************************************************/
        createXadesTCerts(now);

        /* ******************************************************************************
         *
         * Create certs and CRLs for XAdES-X tests
         *
         * *****************************************************************************/

        createXadesXCerts(now);

        } catch (Exception ex)
        {
            throw new RuntimeException("static initialization failed", ex);
        }
    }

    private static void createXadesTCerts(Date now) throws Exception,
            CertificateEncodingException, IOException, CRLException,
            KeyStoreException, NoSuchAlgorithmException, CertificateException,
            InvalidAlgorithmParameterException, NoSuchProviderException
    {
        X509CRL crl;
        test01_T_userCaCert = FullCert.getCACert("RSA", 1024, "CN=XAdES4j Testing CA",
                new Date(now.getTime() - ONE_HOUR_IN_MS),
                new Date(now.getTime() + ONE_HOUR_IN_MS),
                "SHA256withRSA"); /* cert will have serial number: 1 */
        saveCertificate("ca.cer", test01_T_userCaCert.getCertificate());
        System.out.println("CA validity from "
                + test01_T_userCaCert.getCertificate().getNotBefore()
                + " to " + test01_T_userCaCert.getCertificate().getNotAfter());

        test01_T_tsaCaCert = FullCert.getCACert("RSA", 1024, "CN=XAdES4j TSA Testing CA",
                new Date(now.getTime() - ONE_HOUR_IN_MS),
                new Date(now.getTime() + ONE_HOUR_IN_MS),
                "SHA256withRSA"); /* cert will have serial number: 1 */
        saveCertificate("tsaCA.cer", test01_T_userCaCert.getCertificate());
        System.out.println("TSA CA validity from "
                + test01_T_userCaCert.getCertificate().getNotBefore()
                + " to " + test01_T_userCaCert.getCertificate().getNotAfter());

        test01_T_userCert = test01_T_userCaCert.createUserCert("RSA", 1024,
                "CN=User Certificate",
                new Date(now.getTime() - ONE_HOUR_IN_MS),
                new Date(now.getTime() + ONE_HOUR_IN_MS/2),
                new BigInteger("2"), "SHA256withRSA");
        saveCertificate("user.cer", test01_T_userCert.getCertificate());
        System.out.println("user validity from "
                + test01_T_userCert.getCertificate().getNotBefore()
                + " to " + test01_T_userCert.getCertificate().getNotAfter());

        test01_T_tsaCert = test01_T_tsaCaCert.createTSACert("RSA", 1024,
                "CN=XAdES4j Testing TSA",
                new Date(now.getTime() - ONE_HOUR_IN_MS),
                new Date(now.getTime() + ONE_HOUR_IN_MS/2),
                new BigInteger("3"), "SHA256withRSA");
        saveCertificate("tsa.cer", test01_T_tsaCert.getCertificate());
        System.out.println("TSA validity from "
                + test01_T_tsaCert.getCertificate().getNotBefore()
                + " to " + test01_T_tsaCert.getCertificate().getNotAfter());

        List<Object> certList = new ArrayList<Object>();
        certList.add(test01_T_userCaCert.getCertificate());
        test01_T_userCaStore = new JcaCertStore(certList);

        CRLEntries entries = test01_T_userCaCert.new CRLEntries();
        // add fictional entry
        entries.addEntry(new BigInteger("134"), new Date(), CRLReason.keyCompromise);

        crl = test01_T_userCaCert.createCRL("SHA256withRSA",
                new Date(now.getTime() - ONE_HOUR_IN_MS/2),
                new Date(now.getTime() + ONE_HOUR_IN_MS/4),
                new BigInteger("2"),
                entries);
        saveCRL("ca.crl", crl);

        test01_T_tsaCRL_1 = test01_T_tsaCaCert.createCRL("SHA256withRSA",
                new Date(now.getTime() - ONE_HOUR_IN_MS/2),
                new Date(now.getTime() + ONE_HOUR_IN_MS/4),
                new BigInteger("2"),
                entries);
        saveCRL("tsaCA.crl", test01_T_tsaCRL_1);

        test01_T_userCRL_2 = test01_T_userCaCert.createCRL("SHA256withRSA",
                new Date(now.getTime() - ONE_HOUR_IN_MS/60),
                new Date(now.getTime() + ONE_HOUR_IN_MS/3),
                new BigInteger("3"),
                entries);
        saveCRL("ca-3.crl", test01_T_userCRL_2);

        test01_T_tsaCRL_2 = test01_T_tsaCaCert.createCRL("SHA256withRSA",
                new Date(now.getTime() - ONE_HOUR_IN_MS/60),
                new Date(now.getTime() + ONE_HOUR_IN_MS/3),
                new BigInteger("3"),
                entries);
        saveCRL("tsaCA-3.crl", test01_T_tsaCRL_2);

        test01_keyingDataProviderNow =
                new DirectKeyingDataProvider(test01_T_userCert.getCertificate(),
                        test01_T_userCert.getPrivateKey());

        /*
         * Create validation data providers for past
         */
        // create current trust anchors
        test01_T_userTrustAnchors = KeyStore.getInstance(KeyStore.getDefaultType());
        test01_T_userTrustAnchors.load(null);
        TrustedCertificateEntry ca =
                new TrustedCertificateEntry(test01_T_userCaCert.getCertificate());
        test01_T_userTrustAnchors.setEntry("ca", ca, null);
        // create store with additional certificates and CRLs
        Collection<Object> content = new ArrayList<Object>();
        content.add(crl);
        CertStore intermCertsAndCrls = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(content));
        // create validation provider with revocation information from 30m ago
        test01_userCertValidationDataProviderPast30m =
                new PKIXCertificateValidationProvider(test01_T_userTrustAnchors,
                true, intermCertsAndCrls);

        // create current trust anchors
        test01_T_tsaTrustAnchors = KeyStore.getInstance(KeyStore.getDefaultType());
        test01_T_tsaTrustAnchors.load(null);
        TrustedCertificateEntry tsaCA =
                new TrustedCertificateEntry(test01_T_tsaCaCert.getCertificate());
        test01_T_tsaTrustAnchors.setEntry("ca", tsaCA, null);
        // create store with additional certificates and CRLs
        content = new ArrayList<Object>();
        content.add(test01_T_tsaCRL_1);
        content.add(test01_T_tsaCert.getCertificate()); // tsa cert is not added to token
        intermCertsAndCrls = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(content));
        // create validation provider with revocation information from 30m ago
        test01_tsaValidationDataProviderPast30m = new PKIXTSACertificateValidationProvider(
                test01_T_tsaTrustAnchors, true, intermCertsAndCrls);

        /*
         * create validation data providers for now
         */
        // create store with additional certificates and CRLs
        content = new ArrayList<Object>();
        content.add(test01_T_userCRL_2);
        intermCertsAndCrls = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(content));
        // create validation provider with revocation information from now
        test01_userCertValidationDataProviderNow =
                new PKIXCertificateValidationProvider(test01_T_userTrustAnchors,
                true, intermCertsAndCrls);

        // create store with additional certificates and CRLs
        content = new ArrayList<Object>();
        content.add(test01_T_tsaCRL_2);
        content.add(test01_T_tsaCert.getCertificate()); // tsa cert is not added to token
        CertStore tsaIntermCertsAndCrls = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(content));
        // create validation provider with revocation information for TSA
        test01_tsaValidationDataProviderNow = new PKIXTSACertificateValidationProvider(
                test01_T_tsaTrustAnchors, true, tsaIntermCertsAndCrls);
    }

    private static void createXadesXCerts(Date now) throws Exception,
            CertificateEncodingException, KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException,
            InvalidAlgorithmParameterException, NoSuchProviderException
    {
        X509CRL crl;
        List<Object> certList;
        TrustedCertificateEntry ca;
        Collection<Object> content;
        CertStore intermCertsAndCrls;
        TrustedCertificateEntry tsaCA;
        test02_X_userCaCert = FullCert.getCACert(
                "RSA",
                1024,
                "CN=XAdES4j XAdES-X User CA",
                new Date(now.getTime() - ONE_HOUR_IN_MS * 24),
                new Date(now.getTime() - ONE_HOUR_IN_MS * 16),
                "SHA256withRSA");
        System.out.println("\"" + test02_X_userCaCert.getCertificate().getSubjectDN() +
                "\" validity from " + test02_X_userCaCert.getCertificate().getNotBefore()
                + " to " + test02_X_userCaCert.getCertificate().getNotAfter());

        test02_X_tsaCaCert = FullCert.getCACert(
                "RSA",
                1024,
                "CN=XAdES4j XAdES-X TSA Testing CA",
                new Date(now.getTime() - ONE_HOUR_IN_MS * 23),
                new Date(now.getTime() + ONE_HOUR_IN_MS * 2),
                "SHA256withRSA");
        System.out.println("\"" + test02_X_tsaCaCert.getCertificate().getSubjectDN() +
                "\" validity from " + test02_X_tsaCaCert.getCertificate().getNotBefore()
                + " to " + test02_X_tsaCaCert.getCertificate().getNotAfter());

        test02_X_userCert = test02_X_userCaCert.createUserCert(
                "RSA",
                1024,
                "CN=XAdES4j test user",
                new Date(now.getTime() - ONE_HOUR_IN_MS * 22),
                // should be  -16h, temporary fix for problems in xades4j when creating
                // signature with past times, won't matter as the CA is valid to -16h
                new Date(now.getTime() + ONE_HOUR_IN_MS),
                new BigInteger("2"),
                "SHA256withRSA");
        System.out.println("user certificate \"" +
                test02_X_userCert.getCertificate().getSubjectDN() +
                "\" validity from " + test02_X_userCert.getCertificate().getNotBefore()
                + " to " + test02_X_userCert.getCertificate().getNotAfter());


        test02_X_tsa1Cert = test02_X_tsaCaCert.createTSACert(
                "RSA",
                1024,
                "CN=XAdES4j XAdES-X TSA 1",
                new Date(now.getTime() - ONE_HOUR_IN_MS * 21),
                new Date(now.getTime() - ONE_HOUR_IN_MS * 12),
                new BigInteger("1"),
                "SHA256withRSA");
        System.out.println("TSA certificate " +
                test02_X_tsa1Cert.getCertificate().getSubjectDN().toString() +
                " is valid from " +
                test02_X_tsa1Cert.getCertificate().getNotBefore() +
                " to "
                + test02_X_tsa1Cert.getCertificate().getNotAfter());

        CRLEntries entries_test02 = test02_X_userCaCert.new CRLEntries();
        entries_test02.addEntry(
                test02_X_userCert.getCertificate().getSerialNumber(),
                new Date(now.getTime() - ONE_HOUR_IN_MS * 18),
                CRLReason.affiliationChanged);

        crl = test02_X_userCaCert.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - ONE_HOUR_IN_MS * 18),
                new Date(now.getTime() - ONE_HOUR_IN_MS * 17),
                new BigInteger("1"),
                entries_test02);

        test02_X_tsa2Cert = test02_X_tsaCaCert.createTSACert(
                "RSA",
                1024,
                "CN=XAdES4j XAdES-X TSA 2",
                new Date(now.getTime() - ONE_HOUR_IN_MS * 15),
                new Date(now.getTime() + ONE_HOUR_IN_MS),
                new BigInteger("3"),
                "SHA256withRSA");
        System.out.println("Certificate " +
                test02_X_tsa2Cert.getCertificate().getSubjectDN().toString() +
                " is valid from " +
                test02_X_tsa2Cert.getCertificate().getNotBefore() +
                " to " +
                test02_X_tsa2Cert.getCertificate().getNotAfter());

        entries_test02 = test02_X_tsaCaCert.new CRLEntries();

        test02_X_tsaCRL_1 = test02_X_tsaCaCert.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - ONE_HOUR_IN_MS * 19),
                new Date(now.getTime() - ONE_HOUR_IN_MS * 13),
                new BigInteger("4"),
                entries_test02);

        entries_test02.addEntry(
                test02_X_tsa1Cert.getCertificate().getSerialNumber(),
                new Date(now.getTime() - ONE_HOUR_IN_MS * 13),
                CRLReason.cessationOfOperation);

        test02_X_tsaCRL_2 = test02_X_tsaCaCert.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - ONE_HOUR_IN_MS * 13),
                new Date(now.getTime() + ONE_HOUR_IN_MS),
                new BigInteger("5"),
                entries_test02);

        certList = new ArrayList<Object>();
        certList.add(test02_X_userCaCert.getCertificate());
        test02_X_userCaStore = new JcaCertStore(certList);

        test02_X_userTrustAnchors = KeyStore.getInstance(KeyStore.getDefaultType());
        test02_X_userTrustAnchors.load(null);
        ca = new TrustedCertificateEntry(test02_X_userCaCert.getCertificate());
        test02_X_userTrustAnchors.setEntry("ca", ca, null);

        test02_X_tsaTrustAnchors = KeyStore.getInstance(KeyStore.getDefaultType());
        test02_X_tsaTrustAnchors.load(null);
        tsaCA = new TrustedCertificateEntry(test02_X_tsaCaCert.getCertificate());
        test02_X_tsaTrustAnchors.setEntry("tsaCA", tsaCA, null);

        test02_keyingDataproviderNow = new DirectKeyingDataProvider(
                        test02_X_userCert.getCertificate(),
                        test02_X_userCert.getPrivateKey());

        content = new ArrayList<Object>();
        content.add(crl);

        intermCertsAndCrls = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(content));

        test02_userCertValidationDataProviderXCreation =
                new PKIXCertificateValidationProvider(
                        test02_X_userTrustAnchors,
                        true,
                        intermCertsAndCrls);

        content = new ArrayList<Object>();
        content.add(test02_X_tsaCRL_1);
        content.add(test02_X_tsaCRL_2);
        content.add(test02_X_tsa1Cert.getCertificate());

        intermCertsAndCrls = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(content));

        test02_tsaCertValidationDataProviderXCreation =
                new PKIXTSACertificateValidationProvider(
                        test02_X_tsaTrustAnchors,
                        true,
                        intermCertsAndCrls);

        content = new ArrayList<Object>();
        content.add(test02_X_tsa1Cert.getCertificate());
        content.add(test02_X_tsa2Cert.getCertificate());
        content.add(test02_X_tsaCRL_1);
        content.add(test02_X_tsaCRL_2);

        intermCertsAndCrls = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(content));

        test02_tsaCertValidationDataProviderNow =
                new PKIXTSACertificateValidationProvider(
                        test02_X_tsaTrustAnchors,
                        true,
                        intermCertsAndCrls);

        test02_userCertMinimalValidationDataProvider =
                new PKIXCertificateValidationProvider(test02_X_userTrustAnchors,
                        true,
                        emptyCertStore);
        test02_tsaCertMinimalValidationDataProvider =
                new PKIXTSACertificateValidationProvider(test02_X_tsaTrustAnchors,
                        true,
                        emptyCertStore);
    }

    @Test
    public void init() throws Exception
    {
        // cause the static initializer to run
        return;
    }


    /*
     * Generator creates signature with certificates and time stamps created in the past
     *
     * ^
     * | <-- in 1h:
     * |           caCert validity end
     * |
     * | <-- in 30 min:
     * |           userCert validity end
     * |           tsaCert validity end
     * |           CRL (3) validity end
     * |
     * | <-- in 15 min:
     * |           CRL (2) validity end
     * |
     * | <-- *now* (signature validation)
     * |
     * | <- 1m ago:
     * |           CRL (3) creation
     * |
     * | <- 30 min ago:
     * |           CRL (2) creation
     * |           time stamp token creation
     * |
     * | <-- 1h ago:
     * |           caCert creation
     * |           userCert creation
     * |           tsaCert creation
     */

    // test creation of document with time stamp in the past
    @Test
    public void test01_T_sig1() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        // test signing
        SurrogateTimeStampTokenProvider.setTSACert(test01_T_tsaCert, test01_T_userCaStore);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(
                new Date(new Date().getTime() - ONE_HOUR_IN_MS/2),
                new BigInteger("3"));
        System.out.println("SignatureTimeStamp creation date in " +
                "\"document.aged.testT_1s\" is " +
                new Date(new Date().getTime() - ONE_HOUR_IN_MS/2));

        Document doc = getDocument("document.xml");
        Element elemToSign = doc.getDocumentElement();
        XadesSigningProfile signer = new XadesTSigningProfile(test01_keyingDataProviderNow);
        signer.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        new Enveloped(signer.newSigner()).sign(elemToSign);

        outputDocument(doc, "document.aged.testT_1s.xml");
    }

    // test if document can be validated using revocation information published before
    // time stamp generation (TODO should fail if we support grace period)
    @Test
    public void test01_T_ver1() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        // test verification
        XAdESForm f = verifySignature("document.aged.testT_1s.xml",
                new XadesVerificationProfile(test01_userCertValidationDataProviderPast30m,
                        test01_tsaValidationDataProviderPast30m));
        assertEquals(XAdESForm.T, f);
    }

    // test if document can be validated using current revocation information
    @Test
    public void test01_T_ver2() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        // test verification
        XAdESForm f = verifySignature("document.aged.testT_1s.xml",
                new XadesVerificationProfile(test01_userCertValidationDataProviderNow,
                        test01_tsaValidationDataProviderNow));
        assertEquals(XAdESForm.T, f);
    }

    // test if document can be validated if user certificate was revoked after
    // signature was time stamped
    // XXX fails if the CertPathBuilder considers certificate to be revoked before their
    // revocation date
    // BC provider has such behavior for revocation reason unspecified, keyCompromise,
    // aACompromise and few others
    @Test
    public void test01_T_ver3() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        CRLEntries entries = test01_T_userCaCert.new CRLEntries();

        // revoke user certificate 15 min ago
        entries.addEntry(test01_T_userCert.getCertificate().getSerialNumber(),
                new Date(new Date().getTime() - ONE_HOUR_IN_MS/4), CRLReason.unspecified);
        System.out.println("User certificate revoked at " +
                new Date(new Date().getTime() - ONE_HOUR_IN_MS/4));

        // create CRL
        X509CRL revokedCerts = test01_T_userCaCert.createCRL("SHA1withRSA",
                new Date(new Date().getTime() - ONE_HOUR_IN_MS/60), // generated 1 min ago
                new Date(new Date().getTime() + ONE_HOUR_IN_MS/2), // nextUpdate in 30 min
                new BigInteger("4"),
                entries);

        // create validation provider with CRL with revoked user cert
        Collection<Object> content = new ArrayList<Object>();
        content.add(revokedCerts);
        content.add(test01_T_tsaCert.getCertificate()); // tsa cert is not added to token
        CertStore intermCertsAndCrls = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(content));
        CertificateValidationProvider cvp = new PKIXCertificateValidationProvider(
                test01_T_userTrustAnchors, true, intermCertsAndCrls);

        XAdESForm f = verifySignature("document.aged.testT_1s.xml",
                new XadesVerificationProfile(cvp,
                        test01_tsaValidationDataProviderNow));
        assertEquals(XAdESForm.T, f);
    }

    // test if document can be validated if user certificate was revoked after
    // signature was time stamped
    // exact same test as testT_3v, with the change to a more "harmless" revocation
    // reason than unspecified: affiliation changed.
    @Test
    public void test01_T_ver3_1() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        CRLEntries entries = test01_T_userCaCert.new CRLEntries();

        // revoke user certificate 15 min ago
        entries.addEntry(test01_T_userCert.getCertificate().getSerialNumber(),
                new Date(new Date().getTime() - ONE_HOUR_IN_MS/4), CRLReason.affiliationChanged);
        System.out.println("User certificate revoked at " +
                new Date(new Date().getTime() - ONE_HOUR_IN_MS/4));

        // create CRL
        X509CRL revokedCerts = test01_T_userCaCert.createCRL("SHA1withRSA",
                new Date(new Date().getTime() - ONE_HOUR_IN_MS/60), // generated 1 min ago
                new Date(new Date().getTime() + ONE_HOUR_IN_MS/2), // nextUpdate in 30 min
                new BigInteger("4"),
                entries);

        // create validation provider with CRL with revoked user cert
        Collection<Object> content = new ArrayList<Object>();
        content.add(revokedCerts);
        content.add(test01_T_tsaCert.getCertificate()); // tsa cert is not added to token
        CertStore intermCertsAndCrls = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(content));
        CertificateValidationProvider cvp = new PKIXCertificateValidationProvider(
                test01_T_userTrustAnchors, true, intermCertsAndCrls);

        XAdESForm f = verifySignature("document.aged.testT_1s.xml",
                new XadesVerificationProfile(cvp,
                        test01_tsaValidationDataProviderNow));
        assertEquals(XAdESForm.T, f);
    }


    // test if document can be validated if user certificate was revoked before
    // signature was time stamped
    @Test(expected = CannotBuildCertificationPathException.class)
    public void test01_T_ver4() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        CRLEntries entries = test01_T_userCaCert.new CRLEntries();

        // revoke user certificate 45 min ago
        entries.addEntry(test01_T_userCert.getCertificate().getSerialNumber(),
                new Date(new Date().getTime() - 1000*60*45), CRLReason.unspecified);
        System.out.println("User certificate revoked at " +
                new Date(new Date().getTime() - 1000*60*45));

        // create CRL
        X509CRL revokedCerts = test01_T_userCaCert.createCRL("SHA1withRSA",
                new Date(new Date().getTime() - 1000*60), // generated 1 min ago
                new Date(new Date().getTime() + 1000*60*30), // nextUpdate in 30 min
                new BigInteger("4"),
                entries);

        // create validation provider with CRL with revoked user cert
        Collection<Object> content = new ArrayList<Object>();
        content.add(revokedCerts);
        content.add(test01_T_tsaCert.getCertificate()); // tsa cert is not added to token
        CertStore intermCertsAndCrls = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(content));
        CertificateValidationProvider cvp = new PKIXCertificateValidationProvider(
                test01_T_userTrustAnchors, true, intermCertsAndCrls);

        XAdESForm f = verifySignature("document.aged.testT_1s.xml",
                new XadesVerificationProfile(cvp, test01_tsaValidationDataProviderNow));
        assertEquals(XAdESForm.T, f);
    }

    /* SigAndRefsTimeStamp tests
     *
     * worst case scenario for validation that still should validate successfully
     */
    /*  t
     * -24 .User CA validity
     * -23 | .TSA CA validity
     * -22 | | .User cert validity
     * -21 | | | .TSA1 cert validity
     *     | | | |
     * -20 | | | | <---- XAdES-T time stamp (TSA1)
     *     | | | |
     * -19 | | | |   .TSA CA 1st CRL
     * -18 | | | |   | .User CA 1st CRL (user cert revocation)
     *     | | | |   | |
     * -17 ' | ' |   | '
     * -15   |   |   |   .TSA2 cert validity
     *       |   |   |   |
     * -14   |   |   |   | <---- XAdES-X time stamp (TSA2)
     *       |   |   |   |
     * -13   |   |   '   |   .TSA CA 2nd CRL (TSA1 cert revocation)
     * -12   |   '       |   |
     *   0   |           |   |  <---- (now) validation
     *   1   |           '   '
     *   2   '
     */

    // create basic XAdES-T signed document
    @Test
    public void test02_X_sig1() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        SurrogateTimeStampTokenProvider.setTSACert(test02_X_tsa1Cert, test02_X_userCaStore);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(
                new Date(new Date().getTime() - ONE_HOUR_IN_MS * 20),
                new BigInteger("1"));
        System.out.println("SignatureTimeStamp creation date is "
                + new Date(new Date().getTime() - ONE_HOUR_IN_MS * 20));

        Document doc = getDocument("document.xml");
        Element elemToSign = doc.getDocumentElement();
        XadesSigningProfile signer = new XadesTSigningProfile(test02_keyingDataproviderNow);
        signer.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        new Enveloped(signer.newSigner()).sign(elemToSign);

        outputDocument(doc, "document.aged.test02_X_sig1.xml");
    }

    // extend T form to X form
    @Test
    public void test02_X_sig2() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        SurrogateTimeStampTokenProvider.setTSACert(test02_X_tsa2Cert, test02_X_userCaStore);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(
                new Date(new Date().getTime() - ONE_HOUR_IN_MS * 14),
                new BigInteger("2"));

        System.out.println("SigAndRefsTimeStamp creation date is "
                + new Date(new Date().getTime() - ONE_HOUR_IN_MS * 14));

        Document doc = getDocument("document.aged.test02_X_sig1.xml");
        Element signatureNode = getSigElement(doc);

        /*
         * extension of signature to X form must be performed in two steps, first we have
         * to create the XML with needed Properties (CompleteRevocationRefs and
         * CompleteCertificateRefs, that is, C form) and only after that we can add the
         * X form time stamp
         */
        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        formExtProfile.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test02_userCertValidationDataProviderXCreation,
                        test02_tsaCertValidationDataProviderXCreation);
        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();

        // extend T to C
        XAdESVerificationResult res = verifier.verify(signatureNode, null, formExt,
                        XAdESForm.C,
                        new Date(new Date().getTime() - ONE_HOUR_IN_MS * 14));

        assertEquals(res.getSignatureForm(), XAdESForm.T);

        // extend C to X
        res = verifier.verify(signatureNode, null, formExt, XAdESForm.X,
                        new Date(new Date().getTime() - ONE_HOUR_IN_MS * 14));

        assertEquals(res.getSignatureForm(), XAdESForm.C);

        outputDocument(doc, "document.aged.test02_X_sig2.xml");
    }

    // extend X to X-L form
    @Test
    public void test02_X_sig3() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        Document doc = getDocument("document.aged.test02_X_sig2.xml");
        Element signatureNode = getSigElement(doc);

        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test02_userCertValidationDataProviderXCreation,
                        test02_tsaCertValidationDataProviderNow);
        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();

        // extend X to X-L
        XAdESVerificationResult res = verifier.verify(signatureNode, null, formExt,
                XAdESForm.X_L);

        assertEquals(res.getSignatureForm(), XAdESForm.X);

        outputDocument(doc, "document.aged.test02_X_sig3.xml");
    }

    // verify if the X form was properly created
    @Test
    public void test02_X_ver1() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        // test verification
        XAdESForm f = verifySignature("document.aged.test02_X_sig2.xml",
                new XadesVerificationProfile(test02_userCertValidationDataProviderXCreation,
                        test02_tsaCertValidationDataProviderNow));

        assertEquals(XAdESForm.X, f);
    }

    // verify if the X-L form was properly created by using validators with just CA
    // certificates, without CRLs or leaf certificates
    @Test
    public void test02_X_ver2() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        // verify using minimal data (just CA certificates)
        XAdESForm f = verifySignature("document.aged.test02_X_sig3.xml",
                new XadesVerificationProfile(test02_userCertMinimalValidationDataProvider,
                        test02_tsaCertMinimalValidationDataProvider));

        assertEquals(XAdESForm.X_L, f);
    }

    /*
     * end of tests
     */

    // helper method
    private XAdESForm verifySignature(String path,
            XadesVerificationProfile p)
            throws FileNotFoundException, ParserConfigurationException,
            SAXException, IOException, XadesProfileResolutionException, XAdES4jException
    {
        Element signatureNode = getSigElement(getDocument(path));
        XAdESVerificationResult res = p.newVerifier().verify(signatureNode, null);
        return res.getSignatureForm();
    }

    // helper method
    private Element getSigElement(Document document)
    {
        return (Element)document.getElementsByTagNameNS(Constants.SignatureSpecNS,
                Constants._TAG_SIGNATURE).item(0);
    }

    // helper method
    private void outputDocument(Document doc, String path)
            throws TransformerConfigurationException,
            TransformerException, IOException
    {
        path = toDocumentDirFilePath(path);
        TransformerFactory tf = TransformerFactory.newInstance();
        FileOutputStream out = new FileOutputStream(path);
        tf.newTransformer().transform(
                new DOMSource(doc),
                new StreamResult(out));
        out.flush();
        out.getFD().sync();
        out.close();
    }

    // helper method
    private static void saveCRL(String path, X509CRL crl)
            throws CRLException, IOException
    {
        path = "./src/test/cert/aged/" + path;
        FileOutputStream fos = new FileOutputStream(path);
        fos.write(crl.getEncoded());
        fos.close();
        return;
    }

    // helper method
    private String toDocumentDirFilePath(String path)
    {
        return "./src/test/xml/" + path;
    }

    // helper method
    private static void saveCertificate(String path, X509Certificate cert)
        throws CertificateEncodingException, IOException
    {
        path = "./src/test/cert/aged/" + path;
        FileOutputStream fos = new FileOutputStream(path);
        fos.write(cert.getEncoded());
        fos.close();
        return;
    }

    // helper method
    private Document getDocument(String path) throws ParserConfigurationException,
        FileNotFoundException, SAXException, IOException
    {
        path = toDocumentDirFilePath(path);
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new FileInputStream(path));
        Element elem = doc.getDocumentElement();
        DOMHelper.useIdAsXmlId(elem);
        return doc;
    }
}
