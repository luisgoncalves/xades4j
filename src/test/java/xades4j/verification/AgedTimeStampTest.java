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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
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
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.utils.Constants;
import org.bouncycastle.asn1.x509.CRLReason;
import org.junit.FixMethodOrder;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runners.MethodSorters;
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
import static xades4j.utils.SignatureServicesTestBase.toPlatformSpecificFilePath;
import static xades4j.utils.SignatureServicesTestBase.toPlatformSpecificXMLDirFilePath;
import xades4j.utils.XadesProfileResolutionException;
import xades4j.verification.FullCert.CRLEntries;

/**
 * Extensive tests of signer and verifiers with special emphasis on testing time stamp
 * related corner cases.
 *
 * @author Hubert Kario
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
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
    private static KeyStore test02_X_userTrustAnchors;
    private static KeyStore test02_X_tsaTrustAnchors;

    private static KeyingDataProvider test02_keyingDataproviderNow;
    private static CertificateValidationProvider test02_userCertValidationDataProviderXCreation;
    private static TSACertificateValidationProvider test02_tsaCertValidationDataProviderXCreation;
    private static TSACertificateValidationProvider test02_tsaCertValidationDataProviderNow;
    private static CertificateValidationProvider test02_userCertMinimalValidationDataProvider;
    private static TSACertificateValidationProvider test02_tsaCertMinimalValidationDataProvider;

    /*
     * data for XAdES-A (ArchiveTimeStamp) tests
     */
    private static FullCert test03_userCaCert;
    private static FullCert test03_userCert;
    private static FullCert test03_X_tsaCaCert;
    private static FullCert test03_A_tsaCaCert;
    private static FullCert test03_T_tsa1Cert;
    private static FullCert test03_X_tsa2Cert;
    private static FullCert test03_A_tsa3Cert;
    private static X509CRL  test03_X_tsaCRL_1;
    private static X509CRL  test03_X_tsaCRL_2;
    private static X509CRL  test03_A_tsaCRL_3;
    private static KeyStore test03_userTrustAnchors;
    private static KeyStore test03_X_tsaTrustAnchors;
    private static KeyStore test03_A_tsaTrustAnchors;

    private static KeyingDataProvider test03_signatureCreationKeyingDataprovider;
    private static CertificateValidationProvider test03_userCertValidationDataProviderXCreation;
    private static TSACertificateValidationProvider test03_tsaCertValidationDataProviderXCreation;
    private static TSACertificateValidationProvider test03_tsaCertValidationDataProviderACreation;
    private static TSACertificateValidationProvider test03_tsaCertValidationDataProviderAnow;
    /** validation data with only trust anchors (no CRLs or certificates) */
    private static CertificateValidationProvider test03_userCertMinimalValidationDataProvider;
    /** validation data with only trust anchors and current CRLs */
    private static TSACertificateValidationProvider test03_tsaCertMinimalValidationDataProvider;

    /*
     * data for XAdES-A timestamp tests with multiple time stamps
     */
    private static FullCert test04_acmeCA;
    private static FullCert test04_acmePersonalCA;
    private static FullCert test04_willECoyote;
    private static FullCert test04_consterCA;
    private static FullCert test04_consterTSA17ya;
    private static FullCert test04_ascendeusCA;
    private static FullCert test04_ascendeusIssuingCA;
    private static FullCert test04_ascendeusTSA17ya;
    private static FullCert test04_ascendeusTSA13ya;
    private static FullCert test04_carpamaCA;
    private static FullCert test04_carpamaTSA13ya;
    private static FullCert test04_carpamaTSA9ya;
    private static FullCert test04_premoxCA;
    private static FullCert test04_premoxTSA9ya;
    private static FullCert test04_premoxTSA5ya;
    private static FullCert test04_gescapeCA;
    private static FullCert test04_gescapeTSA5ya;
    private static FullCert test04_unibimCA;
    private static FullCert test04_unibimTSA1ya;
    private static FullCert test04_astronCA;
    private static FullCert test04_astronTSA1ya;
    private static CertificateValidationProvider test04_certValidationDataProviderCCreation;
    private static CertificateValidationProvider test04_certValidationDataProviderOnlyTrustAnchors;

    private static final long ONE_HOUR_IN_MS = 60 * 60 * 1000;
    private static final long ONE_DAY_IN_MS = 24 * ONE_HOUR_IN_MS;
    private static final long ONE_WEEK_IN_MS = 7 * ONE_DAY_IN_MS;
    private static final long ONE_YEAR_IN_MS = 52 * ONE_WEEK_IN_MS;

    private static final Date realNow = new Date();

    static
    {
        try {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        System.out.println("AgedTimeStampTest start, current time is " + realNow);

        CertStoreParameters emptyParams = new CollectionCertStoreParameters();
        emptyCertStore = CertStore.getInstance("Collection", emptyParams );

        /* ******************************************************************************
         *
         * Create cryptographic data for XAdES-T tests
         *
         * *****************************************************************************/
        createXadesTCerts(realNow);

        /* ******************************************************************************
         *
         * Create certs and CRLs for XAdES-X tests
         *
         * *****************************************************************************/

        createXadesXCerts(realNow);

        /* ******************************************************************************
         *
         * Create certs and CRLs for XAdES-A tests
         *
         * *****************************************************************************/

        createXadesACerts(realNow);

        /* ******************************************************************************
         *
         * Create certs for XAdES-A with multiple time stamps
         *
         * *****************************************************************************/

        createXadesAmultTSACerts(realNow);

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

        CRLEntries entries = test01_T_userCaCert.new CRLEntries();
        // add fictional entry
        entries.addEntry(new BigInteger("134"), realNow, CRLReason.keyCompromise);

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

    private static void createXadesAmultTSACerts(Date now)
        throws Exception
    {
        test04_acmeCA = FullCert.getCACert(
                "RSA",
                1024,
                "CN=ACME Certification Services CA",
                new Date(now.getTime() - 20 * ONE_YEAR_IN_MS),
                new Date(now.getTime() - 10 * ONE_YEAR_IN_MS),
                "SHA1withRSA");

        test04_acmePersonalCA = test04_acmeCA.createSubCACert(
                "RSA",
                1024,
                "CN=ACME Personal Certificates CA",
                new Date(now.getTime() - 18 * ONE_YEAR_IN_MS),
                new Date(now.getTime() - 13 * ONE_YEAR_IN_MS),
                new BigInteger("2"),
                "SHA1withRSA");

        test04_willECoyote = test04_acmePersonalCA.createUserCert(
                "RSA",
                1024,
                "CN=Will E. Coyote",
                new Date(now.getTime() - 18 * ONE_YEAR_IN_MS + 45 * ONE_WEEK_IN_MS),
                new Date(now.getTime() + ONE_HOUR_IN_MS),
                new BigInteger("2"),
                "SHA1withRSA");

        test04_consterCA = FullCert.getCACert(
                "RSA",
                1024,
                "CN=Conster CA",
                new Date(now.getTime() - 18 * ONE_YEAR_IN_MS),
                new Date(now.getTime() -  8 * ONE_YEAR_IN_MS),
                "SHA1withRSA");

        test04_consterTSA17ya = test04_consterCA.createTSACert(
                "RSA",
                1024,
                "CN=Conster Time Server",
                new Date(now.getTime() - 17 * ONE_YEAR_IN_MS),
                new Date(now.getTime() - 12 * ONE_YEAR_IN_MS),
                new BigInteger("2"),
                "SHA1withRSA");

        test04_ascendeusCA = FullCert.getCACert(
                "RSA",
                1024,
                "CN=Ascendeus Root CA",
                new Date(now.getTime() - 17 * ONE_YEAR_IN_MS - 6 * ONE_WEEK_IN_MS),
                new Date(now.getTime() - 7 * ONE_YEAR_IN_MS),
                "SHA1withRSA");

        test04_ascendeusIssuingCA = test04_ascendeusCA.createSubCACert(
                "RSA",
                1024,
                "CN=Ascendeus Issuing CA",
                new Date(now.getTime() - 17 * ONE_YEAR_IN_MS - 3 * ONE_WEEK_IN_MS),
                new Date(now.getTime() - 7 * ONE_YEAR_IN_MS),
                new BigInteger("2"),
                "SHA1withRSA");

        test04_ascendeusTSA17ya = test04_ascendeusIssuingCA.createTSACert(
                "RSA",
                1024,
                "CN=Ascendeus Time Services",
                new Date(now.getTime() - 17 * ONE_YEAR_IN_MS),
                new Date(now.getTime() - 12 * ONE_YEAR_IN_MS),
                new BigInteger("2"),
                "SHA1withRSA");

        test04_ascendeusTSA13ya = test04_ascendeusIssuingCA.createTSACert(
                "RSA",
                1024,
                "CN=Ascendeus Time Services",
                new Date(now.getTime() - 13 * ONE_YEAR_IN_MS),
                new Date(now.getTime() - 8 * ONE_YEAR_IN_MS),
                new BigInteger("3"),
                "SHA1withRSA");

        test04_carpamaCA = FullCert.getCACert(
                "RSA",
                1024,
                "CN=Carpama Certificate Authority",
                new Date(now.getTime() - 13 * ONE_YEAR_IN_MS - 12 * ONE_WEEK_IN_MS), 
                new Date(now.getTime() - 3 * ONE_YEAR_IN_MS),
                "SHA1withRSA");

        test04_carpamaTSA13ya = test04_carpamaCA.createTSACert(
                "RSA",
                1024,
                "CN=Carpama Time Server",
                new Date(now.getTime() - 13 * ONE_YEAR_IN_MS - 6 * ONE_WEEK_IN_MS),
                new Date(now.getTime() - 8 * ONE_YEAR_IN_MS),
                new BigInteger("3"),
                "SHA1withRSA");

        test04_carpamaTSA9ya = test04_carpamaCA.createTSACert(
                "RSA",
                1024,
                "CN=Carpama Time Server",
                new Date(now.getTime() - 9 * ONE_YEAR_IN_MS - 6 * ONE_WEEK_IN_MS),
                new Date(now.getTime() - 4 * ONE_YEAR_IN_MS),
                new BigInteger("4"),
                "SHA1withRSA");

        test04_premoxCA = FullCert.getCACert(
                "RSA",
                1024,
                "CN=Premox CA",
                new Date(now.getTime() - 9 * ONE_YEAR_IN_MS - 12 * ONE_WEEK_IN_MS),
                new Date(now.getTime() + 1 * ONE_YEAR_IN_MS),
                "SHA256withRSA");

        test04_premoxTSA9ya = test04_premoxCA.createTSACert(
                "RSA",
                1024,
                "CN=Premox TSA",
                new Date(now.getTime() - 9 * ONE_YEAR_IN_MS - 6 * ONE_WEEK_IN_MS),
                new Date(now.getTime() - 4 * ONE_YEAR_IN_MS),
                new BigInteger("2"),
                "SHA256withRSA");

        test04_premoxTSA5ya = test04_premoxCA.createTSACert(
                "RSA",
                1024,
                "CN=Premox TSA",
                new Date(now.getTime() - 5 * ONE_YEAR_IN_MS - 6 * ONE_WEEK_IN_MS),
                new Date(now.getTime() - 6 * ONE_WEEK_IN_MS),
                new BigInteger("3"),
                "SHA256withRSA");

        test04_gescapeCA = FullCert.getCACert(
                "RSA",
                1024,
                "CN=Gescape Certificate Authority",
                new Date(now.getTime() - 5 * ONE_YEAR_IN_MS - 12 * ONE_WEEK_IN_MS),
                new Date(now.getTime() + 6 * ONE_WEEK_IN_MS),
                "SHA256withRSA");

        test04_gescapeTSA5ya = test04_gescapeCA.createTSACert(
                "RSA",
                1024,
                "CN=Gescape Time Stamping Authority",
                new Date(now.getTime() - 5 * ONE_YEAR_IN_MS - 6 * ONE_WEEK_IN_MS),
                new Date(now.getTime() + 6 * ONE_WEEK_IN_MS),
                new BigInteger("2"),
                "SHA256withRSA");

        test04_unibimCA = FullCert.getCACert(
                "RSA",
                2048,
                "CN=Unibim CA",
                new Date(now.getTime() - ONE_YEAR_IN_MS - 12 * ONE_WEEK_IN_MS),
                new Date(now.getTime() + 9 * ONE_YEAR_IN_MS),
                "SHA256withRSA");

        test04_unibimTSA1ya = test04_unibimCA.createTSACert(
                "RSA",
                2048,
                "CN=Unibim TSA",
                new Date(now.getTime() - ONE_YEAR_IN_MS - 6 * ONE_WEEK_IN_MS),
                new Date(now.getTime() + 4 * ONE_YEAR_IN_MS),
                new BigInteger("2"),
                "SHA256withRSA");

        test04_astronCA = FullCert.getCACert(
                "RSA",
                2048,
                "CN=Astron CA",
                new Date(now.getTime() - ONE_YEAR_IN_MS - 12 * ONE_WEEK_IN_MS),
                new Date(now.getTime() + 9 * ONE_YEAR_IN_MS),
                "SHA256withRSA");

        test04_astronTSA1ya = test04_astronCA.createTSACert(
                "RSA",
                2048,
                "CN=Astron TSA",
                new Date(now.getTime() - ONE_YEAR_IN_MS - 6 * ONE_WEEK_IN_MS - 1 * ONE_DAY_IN_MS),
                new Date(now.getTime() + 4 * ONE_YEAR_IN_MS),
                new BigInteger("2"),
                "SHA256withRSA");

        Date cCreatTime = new Date(now.getTime() - 17 * ONE_YEAR_IN_MS
                + 16 * ONE_DAY_IN_MS);
        CRLEntries emptyEntries = test04_acmeCA.new CRLEntries();
        KeyStore trustAnchors = keyStoreForCerts(test04_acmeCA);
        X509CRL acmeCRL = test04_acmeCA.createCRL(
                "SHA1withRSA",
                new Date(cCreatTime.getTime() - 3 * ONE_DAY_IN_MS),
                new Date(now.getTime() + 4 * ONE_DAY_IN_MS),
                new BigInteger("3"),
                emptyEntries);
        X509CRL acmePersonalCRL = test04_acmePersonalCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 8 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 16 * ONE_HOUR_IN_MS),
                new BigInteger("3"),
                emptyEntries);
        Collection<X509CRL> crls = createCRLCollection(acmeCRL, acmePersonalCRL);
        CertStore intermCertsAndCrls = certStoreForCertsAndCrls(crls,
                test04_acmeCA.getCertificate(),
                test04_acmePersonalCA.getCertificate());
        test04_certValidationDataProviderCCreation =
                new PKIXCertificateValidationProvider(trustAnchors, true, intermCertsAndCrls);

        test04_certValidationDataProviderOnlyTrustAnchors =
                new PKIXCertificateValidationProvider(trustAnchors, true, emptyCertStore);
    }

    private static void createXadesXCerts(Date now) throws Exception,
            CertificateEncodingException, KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException,
            InvalidAlgorithmParameterException, NoSuchProviderException
    {
        X509CRL crl;
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
                new BigInteger("2"),
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
        content = new ArrayList<Object>();
        content.add(test02_X_tsaCRL_2);

        intermCertsAndCrls = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(content));
        test02_tsaCertMinimalValidationDataProvider =
                new PKIXTSACertificateValidationProvider(test02_X_tsaTrustAnchors,
                        true,
                        emptyCertStore);
    }

    private static void createXadesACerts(Date now)
            throws Exception, CertificateEncodingException, KeyStoreException,
            IOException, NoSuchAlgorithmException, CertificateException,
            InvalidAlgorithmParameterException, NoSuchProviderException
    {
        test03_userCaCert = FullCert.getCACert(
                "RSA",
                1024,
                "CN=XAdES-A testing User CA",
                new Date(now.getTime() - 24 * ONE_HOUR_IN_MS),
                new Date(now.getTime() - 17 * ONE_HOUR_IN_MS),
                "SHA256withRSA");

        test03_X_tsaCaCert = FullCert.getCACert(
                "RSA",
                1024,
                "CN=XAdES-A testing X form TSA CA",
                new Date(now.getTime() - 23 * ONE_HOUR_IN_MS),
                new Date(now.getTime() - 9 * ONE_HOUR_IN_MS),
                "SHA256withRSA");

        test03_userCert = test03_userCaCert.createUserCert(
                "RSA",
                1024,
                "CN=XAdes-A testing User cert",
                new Date(now.getTime() - 22 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + ONE_HOUR_IN_MS),
                new BigInteger("2"),
                "SHA256withRSA");

        test03_T_tsa1Cert = test03_X_tsaCaCert.createTSACert(
                "RSA",
                1024,
                "CN=XAdES-A testing T form TSA",
                new Date(now.getTime() - 21 * ONE_HOUR_IN_MS),
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new BigInteger("2"),
                "SHA256withRSA");

        CRLEntries tsaCaCrlEntries = test03_X_tsaCaCert.new CRLEntries();
        test03_X_tsaCRL_1 = test03_X_tsaCaCert.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 19 * ONE_HOUR_IN_MS),
                new Date(now.getTime() - 13 * ONE_HOUR_IN_MS),
                new BigInteger("1"),
                tsaCaCrlEntries);

        CRLEntries userCaCrlEntries = test03_userCaCert.new CRLEntries();
        userCaCrlEntries.addEntry(
                test03_userCert.getCertificate().getSerialNumber(),
                new Date(now.getTime() - 18 * ONE_HOUR_IN_MS),
                CRLReason.affiliationChanged);
        X509CRL userCaCrl = test03_userCaCert.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 18 * ONE_HOUR_IN_MS),
                new Date(now.getTime() - 17 * ONE_HOUR_IN_MS),
                new BigInteger("1"),
                userCaCrlEntries);

        test03_X_tsa2Cert = test03_X_tsaCaCert.createTSACert(
                "RSA",
                1024,
                "CN=XAdES-A testing X form TSA",
                new Date(now.getTime() - 15 * ONE_HOUR_IN_MS),
                new Date(now.getTime() - 9 * ONE_HOUR_IN_MS),
                new BigInteger("3"),
                "SHA256withRSA");

        tsaCaCrlEntries.addEntry(
                test03_T_tsa1Cert.getCertificate().getSerialNumber(),
                new Date(now.getTime() - 13 * ONE_HOUR_IN_MS),
                CRLReason.affiliationChanged);
        test03_X_tsaCRL_2 = test03_X_tsaCaCert.createCRL("SHA256withRSA",
                new Date(now.getTime() - 13 * ONE_HOUR_IN_MS),
                new Date(now.getTime() - 9 * ONE_HOUR_IN_MS),
                new BigInteger("3"),
                tsaCaCrlEntries);

        test03_A_tsaCaCert = FullCert.getCACert(
                "RSA",
                1024,
                "CN=XAdES-A testing A form TSA CA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + ONE_HOUR_IN_MS),
                "SHA256withRSA");

        test03_A_tsa3Cert = test03_A_tsaCaCert.createTSACert(
                "RSA",
                1024,
                "CN=XAdES-A testing A form TSA",
                new Date(now.getTime() - 11 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + ONE_HOUR_IN_MS),
                new BigInteger("2"),
                "SHA256withRSA");

        tsaCaCrlEntries = test03_A_tsaCaCert.new CRLEntries();
        test03_A_tsaCRL_3 = test03_A_tsaCaCert.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 1 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + ONE_HOUR_IN_MS),
                new BigInteger("1"),
                tsaCaCrlEntries);

        test03_signatureCreationKeyingDataprovider = new DirectKeyingDataProvider(
                test03_userCert.getCertificate(),
                test03_userCert.getPrivateKey());

        test03_userTrustAnchors = KeyStore.getInstance(KeyStore.getDefaultType());
        test03_userTrustAnchors.load(null);
        TrustedCertificateEntry ca = new TrustedCertificateEntry(test03_userCaCert.getCertificate());
        test03_userTrustAnchors.setEntry("ca", ca, null);

        List<Object> content = new ArrayList<Object>();
        content.add(userCaCrl);
        CertStore userIntermCertsAndCrlsXCreation = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(content));

        test03_userCertValidationDataProviderXCreation =
                new PKIXCertificateValidationProvider(test03_userTrustAnchors,
                        true,
                        userIntermCertsAndCrlsXCreation);

        test03_X_tsaTrustAnchors = KeyStore.getInstance(KeyStore.getDefaultType());
        test03_X_tsaTrustAnchors.load(null);
        ca = new TrustedCertificateEntry(test03_X_tsaCaCert.getCertificate());
        test03_X_tsaTrustAnchors.setEntry("ca", ca, null);

        content = new ArrayList<Object>();
        content.add(test03_T_tsa1Cert.getCertificate());
        content.add(test03_X_tsaCRL_1);
        CertStore xTsaIntermCertsAndCrlsXCreation = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(content));

        test03_tsaCertValidationDataProviderXCreation =
                new PKIXTSACertificateValidationProvider(
                        test03_X_tsaTrustAnchors,
                        true,
                        xTsaIntermCertsAndCrlsXCreation);

        test03_A_tsaTrustAnchors = KeyStore.getInstance(KeyStore.getDefaultType());
        test03_A_tsaTrustAnchors.load(null);
        ca = new TrustedCertificateEntry(test03_X_tsaCaCert.getCertificate());
        test03_A_tsaTrustAnchors.setEntry("ca", ca, null);
        ca = new TrustedCertificateEntry(test03_A_tsaCaCert.getCertificate());
        test03_A_tsaTrustAnchors.setEntry("newCA", ca, null);

        content = new ArrayList<Object>();
        content.add(test03_T_tsa1Cert.getCertificate());
        content.add(test03_X_tsa2Cert.getCertificate());
        content.add(test03_X_tsaCRL_1);
        content.add(test03_X_tsaCRL_2);
        CertStore aTsaIntermCertsAndCrlsACreation = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(content));
        test03_tsaCertValidationDataProviderACreation =
                new PKIXTSACertificateValidationProvider(
                        test03_A_tsaTrustAnchors,
                        true,
                        aTsaIntermCertsAndCrlsACreation);

        content = new ArrayList<Object>();
        content.add(test03_A_tsa3Cert.getCertificate());
        content.add(test03_A_tsaCRL_3);

        CertStore aValidationCertsAndCrls = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(content));

        test03_tsaCertValidationDataProviderAnow =
                new PKIXTSACertificateValidationProvider(
                        test03_A_tsaTrustAnchors,
                        true,
                        aValidationCertsAndCrls);

        test03_userCertMinimalValidationDataProvider =
                new PKIXCertificateValidationProvider(
                        test03_userTrustAnchors,
                        true,
                        emptyCertStore);

        content = new ArrayList<Object>();
        content.add(test03_A_tsaCRL_3);
        CertStore aValidationCrlsOnly = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(content));
        test03_tsaCertMinimalValidationDataProvider =
                new PKIXTSACertificateValidationProvider(
                        test03_A_tsaTrustAnchors,
                        true,
                        aValidationCrlsOnly);
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
    public void test01_01_T_sig1() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        // test signing
        SurrogateTimeStampTokenProvider.setTSACert(test01_T_tsaCert);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(
                new Date(realNow.getTime() - ONE_HOUR_IN_MS/2),
                new BigInteger("3"));
        System.out.println("SignatureTimeStamp creation date in " +
                "\"document.aged.testT_1s\" is " +
                new Date(realNow.getTime() - ONE_HOUR_IN_MS/2));

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
    public void test01_02_T_ver1() throws Exception
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
    public void test01_03_T_ver2() throws Exception
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
    @Ignore
    public void test01_04_T_ver3() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        CRLEntries entries = test01_T_userCaCert.new CRLEntries();

        // revoke user certificate 15 min ago
        entries.addEntry(test01_T_userCert.getCertificate().getSerialNumber(),
                new Date(realNow.getTime() - ONE_HOUR_IN_MS/4), CRLReason.unspecified);
        System.out.println("User certificate revoked at " +
                new Date(realNow.getTime() - ONE_HOUR_IN_MS/4));

        // create CRL
        X509CRL revokedCerts = test01_T_userCaCert.createCRL("SHA1withRSA",
                new Date(realNow.getTime() - ONE_HOUR_IN_MS/60), // generated 1 min ago
                new Date(realNow.getTime() + ONE_HOUR_IN_MS/2), // nextUpdate in 30 min
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
    public void test01_05_T_ver3_1() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        CRLEntries entries = test01_T_userCaCert.new CRLEntries();

        // revoke user certificate 15 min ago
        entries.addEntry(test01_T_userCert.getCertificate().getSerialNumber(),
                new Date(realNow.getTime() - ONE_HOUR_IN_MS/4), CRLReason.affiliationChanged);
        System.out.println("User certificate revoked at " +
                new Date(realNow.getTime() - ONE_HOUR_IN_MS/4));

        // create CRL
        X509CRL revokedCerts = test01_T_userCaCert.createCRL("SHA1withRSA",
                new Date(realNow.getTime() - ONE_HOUR_IN_MS/60), // generated 1 min ago
                new Date(realNow.getTime() + ONE_HOUR_IN_MS/2), // nextUpdate in 30 min
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
    public void test01_06_T_ver4() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        CRLEntries entries = test01_T_userCaCert.new CRLEntries();

        // revoke user certificate 45 min ago
        entries.addEntry(test01_T_userCert.getCertificate().getSerialNumber(),
                new Date(realNow.getTime() - 1000*60*45), CRLReason.unspecified);
        System.out.println("User certificate revoked at " +
                new Date(realNow.getTime() - 1000*60*45));

        // create CRL
        X509CRL revokedCerts = test01_T_userCaCert.createCRL("SHA1withRSA",
                new Date(realNow.getTime() - 1000*60), // generated 1 min ago
                new Date(realNow.getTime() + 1000*60*30), // nextUpdate in 30 min
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
    public void test02_01_X_sig1() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());
        String outFileName = new String("document.aged.test02_X_sig1.xml");
        removeFile(outFileName);

        SurrogateTimeStampTokenProvider.setTSACert(test02_X_tsa1Cert);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(
                new Date(realNow.getTime() - ONE_HOUR_IN_MS * 20),
                new BigInteger("1"));
        System.out.println("SignatureTimeStamp creation date is "
                + new Date(realNow.getTime() - ONE_HOUR_IN_MS * 20));

        Document doc = getDocument("document.xml");
        Element elemToSign = doc.getDocumentElement();
        XadesSigningProfile signer = new XadesTSigningProfile(test02_keyingDataproviderNow);
        signer.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        new Enveloped(signer.newSigner()).sign(elemToSign);

        outputDocument(doc, outFileName);
    }

    // extend T form to X form
    @Test
    public void test02_02_X_sig2() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());
        String outFileName = new String("document.aged.test02_X_sig2.xml");
        removeFile(outFileName);

        SurrogateTimeStampTokenProvider.setTSACert(test02_X_tsa2Cert);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(
                new Date(realNow.getTime() - ONE_HOUR_IN_MS * 14),
                new BigInteger("2"));

        System.out.println("SigAndRefsTimeStamp creation date is "
                + new Date(realNow.getTime() - ONE_HOUR_IN_MS * 14));

        Document doc = getOutputDocument("document.aged.test02_X_sig1.xml");
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
        Date now = new Date(realNow.getTime() - ONE_HOUR_IN_MS * 14);
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().setDefaultVerificationDate(now);

        // extend T to C
        XAdESVerificationResult res = verifier.verify(signatureNode, options, formExt,
                XAdESForm.C);

        assertEquals(res.getSignatureForm(), XAdESForm.T);

        // extend C to X
        res = verifier.verify(signatureNode, options, formExt, XAdESForm.X);

        assertEquals(res.getSignatureForm(), XAdESForm.C);

        outputDocument(doc, outFileName);
    }

    // extend X to X-L form
    @Test
    public void test02_03_X_sig3() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());
        String outFileName = new String("document.aged.test02_X_sig3.xml");
        removeFile(outFileName);

        Document doc = getOutputDocument("document.aged.test02_X_sig2.xml");
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

        outputDocument(doc, outFileName);
    }

    // verify if the X form was properly created
    @Test
    public void test02_04_X_ver1() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        // test verification
        XAdESForm f = verifySignature("document.aged.test02_X_sig2.xml",
                new XadesVerificationProfile(test02_userCertValidationDataProviderXCreation,
                        test02_tsaCertValidationDataProviderNow));

        assertEquals(XAdESForm.X, f);
    }

    // verify if the X-L form was properly created by using validators with just CA
    // certificates and current CRLs for TSA
    @Test
    public void test02_05_X_ver2() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        // verify using minimal data (just CA certificates)
        XAdESForm f = verifySignature("document.aged.test02_X_sig3.xml",
                new XadesVerificationProfile(test02_userCertMinimalValidationDataProvider,
                        test02_tsaCertMinimalValidationDataProvider));

        assertEquals(XAdESForm.X_L, f);
    }

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
     * -12   |   '       |   | .Arch-TSA CA validity
     * -11   |           |   | | .Arch-TSA3 validity
     *       |           |   | | |
     * -10   |           |   | | | <---- first XAdES-A time stamp (Arch-TSA1)
     *  -9   '           '   ' | |
     *  -1                     | | .Arch-TSA CA 1st CRL
     *                         | | |
     *   0                     | | | <--- (now) validaiton
     *                         | | |
     *   1                     ' ' '
     */

    // create basic XAdES-T signed document
    @Test
    public void test03_01_T_sig1() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());
        String outFileName = new String("document.aged.test03_T_sig1.xml");
        removeFile(outFileName);

        SurrogateTimeStampTokenProvider.setTSACert(test03_T_tsa1Cert);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(
                new Date(realNow.getTime() - ONE_HOUR_IN_MS * 20),
                new BigInteger("1"));
        System.out.println("SignatureTimeStamp creation date is "
                + new Date(realNow.getTime() - ONE_HOUR_IN_MS * 20));

        Document doc = getDocument("document.xml");
        Element elemToSign = doc.getDocumentElement();
        XadesSigningProfile signer = new XadesTSigningProfile(test03_signatureCreationKeyingDataprovider);
        signer.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        new Enveloped(signer.newSigner()).sign(elemToSign);

        outputDocument(doc, outFileName);
    }

    // extend T form to X form
    @Test
    public void test03_02_X_sig2() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());
        String outFileName = new String("document.aged.test03_X_sig2.xml");
        removeFile(outFileName);

        Date now = new Date(realNow.getTime() - ONE_HOUR_IN_MS * 14);
        SurrogateTimeStampTokenProvider.setTSACert(test03_X_tsa2Cert);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(
                now,
                new BigInteger("2"));

        System.out.println("SigAndRefsTimeStamp creation date is "
                + now);

        Document doc = getOutputDocument("document.aged.test03_T_sig1.xml");
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
                        test03_userCertValidationDataProviderXCreation,
                        test03_tsaCertValidationDataProviderXCreation);
        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().setDefaultVerificationDate(now);

        // extend T to C
        XAdESVerificationResult res = verifier.verify(signatureNode, options, formExt,
                XAdESForm.C);

        assertEquals(res.getSignatureForm(), XAdESForm.T);

        // extend C to X
        res = verifier.verify(signatureNode, options, formExt, XAdESForm.X);

        assertEquals(res.getSignatureForm(), XAdESForm.C);

        outputDocument(doc, outFileName);
    }

    // extend X to X-L form
    @Test
    public void test03_03_X_sig3() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());
        String outFileName = new String("document.aged.test03_X_sig3.xml");
        removeFile(outFileName);

        Document doc = getOutputDocument("document.aged.test03_X_sig2.xml");
        Element signatureNode = getSigElement(doc);

        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test03_userCertValidationDataProviderXCreation,
                        test03_tsaCertValidationDataProviderACreation);
        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();
        Date now = new Date(realNow.getTime() - 10 * ONE_HOUR_IN_MS);
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().setDefaultVerificationDate(now);

        // extend X to X-L
        XAdESVerificationResult res = verifier.verify(signatureNode, options, formExt,
                XAdESForm.X_L);

        assertEquals(res.getSignatureForm(), XAdESForm.X);

        outputDocument(doc, outFileName);
    }

    // extend X-L form to A form
    @Test
    public void test03_04_A_sig4() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());
        String outFileName = new String("document.aged.test03_A_sig4.xml");
        removeFile(outFileName);

        Date now = new Date(realNow.getTime() - ONE_HOUR_IN_MS * 10);
        SurrogateTimeStampTokenProvider.setTSACert(test03_A_tsa3Cert);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(
                now,
                new BigInteger("2"));

        System.out.println("ArchiveTimeStamp creation date is "
                + now);

        Document doc = getOutputDocument("document.aged.test03_X_sig3.xml");
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
                        test03_userCertValidationDataProviderXCreation,
                        test03_tsaCertValidationDataProviderAnow);
        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().setDefaultVerificationDate(new Date(realNow.getTime() - ONE_HOUR_IN_MS * 14));

        // extend X-L to A
        XAdESVerificationResult res = verifier.verify(signatureNode, options, formExt,
                XAdESForm.A);

        assertEquals(res.getSignatureForm(), XAdESForm.X_L);

        outputDocument(doc, outFileName);
    }

    // verify A form
    @Test
    public void test03_05_A_ver1() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        // test verification
        XAdESForm f = verifySignature("document.aged.test03_A_sig4.xml",
                new XadesVerificationProfile(test03_userCertValidationDataProviderXCreation,
                        test03_tsaCertValidationDataProviderAnow));

        assertEquals(XAdESForm.A, f);
    }

    // add validation info to A form
    @Test
    public void test03_06_A_sig5() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());
        String outFileName = new String("document.aged.test03_A_sig5.xml");
        removeFile(outFileName);

        Document doc = getOutputDocument("document.aged.test03_A_sig4.xml");
        Element signatureNode = getSigElement(doc);

        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        formExtProfile.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test03_userCertValidationDataProviderXCreation,
                        test03_tsaCertValidationDataProviderAnow);
        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();

        // extend A to A-VD
        XAdESVerificationResult res = verifier.verify(signatureNode, null, formExt,
                        XAdESForm.A_VD);

        assertEquals(res.getSignatureForm(), XAdESForm.A);

        outputDocument(doc, outFileName);
    }

    // verify A form using minimal validators
    @Test
    public void test03_07_A_ver2() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());

        // verify using minimal data (just CA certificates)
        XAdESForm f = verifySignature("document.aged.test03_A_sig5.xml",
                new XadesVerificationProfile(test03_userCertMinimalValidationDataProvider,
                        test03_tsaCertMinimalValidationDataProvider));

        assertEquals(XAdESForm.A, f);
    }

    // time stamp A(VD) form again
    @Test
    public void test03_08_A_sig6() throws Exception
    {
        System.out.println(Thread.currentThread().getStackTrace()[1].getMethodName());
        String outFileName = new String("document.aged.test03_A_sig6.xml");
        removeFile(outFileName);

        SurrogateTimeStampTokenProvider.setTSACert(test03_A_tsa3Cert);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(
                realNow,
                new BigInteger("3"));

        System.out.println("ArchiveTimeStamp creation date is "
                + realNow);

        Document doc = getOutputDocument("document.aged.test03_A_sig5.xml");
        Element signatureNode = getSigElement(doc);

        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        formExtProfile.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test03_userCertValidationDataProviderXCreation,
                        test03_tsaCertValidationDataProviderAnow);
        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();

        // extend A to A (add ArchiveTimeStamp)
        XAdESVerificationResult res = verifier.verify(signatureNode, null, formExt,
                        XAdESForm.A);

        assertEquals(res.getSignatureForm(), XAdESForm.A);

        outputDocument(doc, outFileName);
    }

    /* Tests with multiple Time Stamping Authorities and realistic time periods
     *
     * quick overview:
     *   t
     * -17y    -- Signature creation
     * -17y ̣   -- XAdES-T form creation (2 time stamps) (consterTSA and ascendeusTSA) 
     * -17y+16d-- XAdES-C form creation
     * -13y    -- XAdES-X form creation (2 time stamps) (ascendeusTSA and carpamaTSA)
     * -13y+2w -- XAdES-X-L form creation
     *  -9y    -- XAdES-A form creation (2 time stamps, 1st set) (carpamaTSA and premoxTSA)
     *  -9y+2w -- XAdES-A with validation data
     *  -5y    -- extending XAdES-A with new set of timestamps (2 timestamps, 2nd set) (premoxTSA and gescapeTSA)
     *  -5y+2w -- adding validation data
     *  -1y    -- extending XAdES-A with new set of timestamps (2 timestamps, 3rd set) (unibimTSA and astronTSA)
     *  -1y+2w -- adding validation data
     *  now    -- validation with currently available revocation data
     *
     * Certificate authorities hierarchy:
     *
     * ACME Certification Services CA
     * |
     * + Will E. Coyote
     *
     * Conster CA
     * |
     * + Conster Time Server (5 years)
     *
     * Ascendeus Root CA (10 years)
     * |
     * + Ascendeus Issuing CA (8 years)
     *   |
     *   + Ascendeus Time Services (5 years)
     *   |
     *   + Ascendeus Time Services (2nd) (5 years)
     *
     * Carpama Certificate Authority (10 years)
     * |
     * + Carpama Time Server (5 years)
     * |
     * + Carpama Time Server (2nd) (5 years)
     *
     * Premox CA (10 years)
     * |
     * + Premox TSA (5 years)
     * |
     * + Premox TSA (2nd) (5 years)
     *
     * Gescape CA (10 years)
     * |
     * + Gescape TSA (5 years)
     *
     * Unibim CA (10 years)
     * |
     * + Unibim TSA (5 years)
     *
     * Astron CA (10 years)
     * |
     * + Astron TSA (5 years)
     */

    // create XAdES-T form
    @Test
    public void test04_01_T_sig1() throws Exception
    {
        System.out.println("test04_T_sig1");

        Date now = new Date(realNow.getTime() - 17 * ONE_YEAR_IN_MS);

        KeyingDataProvider keyingDataProvider = new DirectKeyingDataProvider(
                test04_willECoyote.getCertificate(),
                test04_willECoyote.getPrivateKey());

        SurrogateTimeStampTokenProvider.setTSACert(test04_consterTSA17ya);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(now, new BigInteger("3"));

        Document doc = getDocument("document.xml");
        Element elemToSign = doc.getDocumentElement();
        XadesSigningProfile signer = new XadesTSigningProfile(keyingDataProvider);
        signer.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        new Enveloped(signer.newSigner()).sign(elemToSign);

        outputDocument(doc, "document.aged.test04.T.xml");
    }

    // add second XAdES-T time stamp
    @Test
    public void test04_02_T_sig2() throws Exception
    {
        System.out.println("test04_T_sig2");

        Date now = new Date(realNow.getTime() - 17 * ONE_YEAR_IN_MS
                + 2 * ONE_HOUR_IN_MS);

        SurrogateTimeStampTokenProvider.setTSACert(test04_ascendeusTSA17ya);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(now, new BigInteger("34"));

        Document doc = getOutputDocument("document.aged.test04.T.xml");
        Element signatureNode = getSigElement(doc);

        KeyStore trustAnchors = keyStoreForCerts(test04_acmeCA);
        final CRLEntries emptyEntries = test04_acmeCA.new CRLEntries();
        X509CRL acmeCRL = test04_acmeCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 6 * ONE_DAY_IN_MS),
                new Date(now.getTime() + ONE_DAY_IN_MS),
                new BigInteger("2"),
                emptyEntries);
        X509CRL acmePcCRL = test04_acmePersonalCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("2"),
                emptyEntries);
        Collection<X509CRL> crls = createCRLCollection(acmeCRL, acmePcCRL);
        CertStore intermCertsAndCrls = certStoreForCertsAndCrls(
                crls,
                test04_acmeCA.getCertificate(),
                test04_acmePersonalCA.getCertificate(),
                test04_willECoyote.getCertificate());
        CertificateValidationProvider certValidationDataProvider =
                new PKIXCertificateValidationProvider(trustAnchors,
                        true,
                        intermCertsAndCrls);

        KeyStore tsaTrustAnchors = keyStoreForCerts(test04_consterCA);
        X509CRL consterCRL = test04_consterCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("2"),
                emptyEntries);
        X509CRL ascendusCRL = test04_ascendeusCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 2 * ONE_DAY_IN_MS),
                new Date(now.getTime() + 5 * ONE_DAY_IN_MS),
                new BigInteger("2"),
                emptyEntries);
        X509CRL ascendusIssuingCRL = test04_ascendeusIssuingCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 18 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 6 * ONE_HOUR_IN_MS),
                new BigInteger("2"),
                emptyEntries);
        Collection<X509CRL> tsaCRLs = createCRLCollection(consterCRL,
                ascendusCRL,
                ascendusIssuingCRL);
        CertStore tsaIntermCertsAndCrls = certStoreForCertsAndCrls(
                tsaCRLs,
                test04_consterCA.getCertificate(),
                test04_consterTSA17ya.getCertificate(),
                test04_ascendeusCA.getCertificate(),
                test04_ascendeusIssuingCA.getCertificate(),
                test04_ascendeusTSA17ya.getCertificate());
        TSACertificateValidationProvider tsaValidationDataProvider =
                new PKIXTSACertificateValidationProvider(tsaTrustAnchors,
                        true,
                        tsaIntermCertsAndCrls);

        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        formExtProfile.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        certValidationDataProvider,
                        tsaValidationDataProvider);

        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().setDefaultVerificationDate(now);

        // add second T time stamp
        XAdESVerificationResult res = verifier.verify(signatureNode, options, formExt,
                XAdESForm.T);

        assertEquals(res.getSignatureForm(), XAdESForm.T);

        outputDocument(doc, "document.aged.test04.T2.xml");
    }

    // add references to signature data
    @Test
    public void test04_03_C_sig3() throws Exception
    {
        System.out.println("test04_C_sig3");

        final Date now = new Date(realNow.getTime() - 17 * ONE_YEAR_IN_MS
                + 16 * ONE_DAY_IN_MS);
        final CRLEntries emptyEntries = test04_ascendeusCA.new CRLEntries();

        Document doc = getOutputDocument("document.aged.test04.T2.xml");
        Element signatureNode = getSigElement(doc);

        KeyStore tsaTrustAnchors = keyStoreForCerts(
                test04_ascendeusCA,
                test04_consterCA);
        X509CRL ascendeusCRL = test04_ascendeusCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 1 * ONE_DAY_IN_MS),
                new Date(now.getTime() + 6 * ONE_DAY_IN_MS),
                new BigInteger("3"),
                emptyEntries);
        X509CRL ascendeusIssuingCRL = test04_ascendeusIssuingCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("3"),
                emptyEntries);
        X509CRL consterCRL = test04_consterCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 20 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 1  * ONE_HOUR_IN_MS),
                new BigInteger("3"),
                emptyEntries);
        Collection<X509CRL> tsaCRLs = createCRLCollection(
                ascendeusCRL,
                ascendeusIssuingCRL,
                consterCRL);
        CertStore tsaIntermCertsAndCrls = certStoreForCertsAndCrls(tsaCRLs,
                test04_ascendeusCA.getCertificate(),
                test04_ascendeusIssuingCA.getCertificate(),
                test04_ascendeusTSA17ya.getCertificate(),
                test04_consterCA.getCertificate(),
                test04_consterTSA17ya.getCertificate());
        TSACertificateValidationProvider tsaValidationDataProvider =
                new PKIXTSACertificateValidationProvider(tsaTrustAnchors,
                        true,
                        tsaIntermCertsAndCrls);

        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        // it shouldn't be used now, as it is not configured, it will throw an exception
        formExtProfile.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test04_certValidationDataProviderCCreation,
                        tsaValidationDataProvider);

        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().setDefaultVerificationDate(now);

        XAdESVerificationResult res = verifier.verify(signatureNode, options, formExt,
                XAdESForm.C);

        assertEquals(res.getSignatureForm(), XAdESForm.T);

        outputDocument(doc, "document.aged.test04_C.xml");
    }

    // add second type of time stamp to signature (SigAndRefsTimeStamp)
    @Test
    public void test04_04_X_sig4() throws Exception
    {
        System.out.println("test04_X_sig4");
        Date now = new Date(realNow.getTime() - 13 * ONE_YEAR_IN_MS);
        SurrogateTimeStampTokenProvider.setTSACert(test04_ascendeusTSA13ya);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(now, new BigInteger("35"));

        Document doc = getOutputDocument("document.aged.test04_C.xml");
        Element signatureNode = getSigElement(doc);
        KeyStore tsaTrustAnchors = keyStoreForCerts(
                test04_consterCA,
                test04_ascendeusCA,
                test04_carpamaCA);

        final CRLEntries emptyEntries = test04_consterCA.new CRLEntries();
        X509CRL consterCRL = test04_consterCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 7 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 17 * ONE_HOUR_IN_MS),
                new BigInteger("4"),
                emptyEntries );
        X509CRL ascendeusCRL = test04_ascendeusCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 2 * ONE_DAY_IN_MS),
                new Date(now.getTime() + 5 * ONE_DAY_IN_MS),
                new BigInteger("4"),
                emptyEntries);
        X509CRL ascendeusIssuingCRL = test04_ascendeusIssuingCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("4"),
                emptyEntries);
        X509CRL carpamaCRL = test04_carpamaCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 4 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 4 * ONE_HOUR_IN_MS),
                new BigInteger("4"),
                emptyEntries);
        Collection<X509CRL> tsaCRLs =createCRLCollection(
                consterCRL,
                ascendeusCRL,
                ascendeusIssuingCRL,
                carpamaCRL);
        CertStore tsaIntermCertsAndCrls = certStoreForCertsAndCrls(tsaCRLs,
                test04_consterCA.getCertificate(),
                test04_consterTSA17ya.getCertificate(),
                test04_ascendeusCA.getCertificate(),
                test04_ascendeusIssuingCA.getCertificate(),
                test04_ascendeusTSA17ya.getCertificate(),
                test04_ascendeusTSA13ya.getCertificate(),
                test04_carpamaCA.getCertificate(),
                test04_carpamaTSA13ya.getCertificate());
        TSACertificateValidationProvider tsaValidationDataProvider =
                new PKIXTSACertificateValidationProvider(
                        tsaTrustAnchors,
                        true,
                        tsaIntermCertsAndCrls);
        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        formExtProfile.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test04_certValidationDataProviderCCreation,
                        tsaValidationDataProvider);

        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().setDefaultVerificationDate(now);

        XAdESVerificationResult res = verifier.verify(signatureNode, options, formExt,
                XAdESForm.X);

        assertEquals(res.getSignatureForm(), XAdESForm.C);

        outputDocument(doc, "document.aged.test04.X.xml");
    }

    // add second SigAndRefsTimeStamp
    @Test
    public void test04_05_X_sig5() throws Exception
    {
        System.out.println("test04_X_sig5");
        Date now = new Date(realNow.getTime() - 13 * ONE_YEAR_IN_MS + ONE_HOUR_IN_MS / 2);
        SurrogateTimeStampTokenProvider.setTSACert(test04_carpamaTSA13ya);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(now, new BigInteger("36"));

        Document doc = getOutputDocument("document.aged.test04.X.xml");
        Element signatureNode = getSigElement(doc);
        KeyStore tsaTrustAnchors = keyStoreForCerts(
                test04_consterCA,
                test04_ascendeusCA,
                test04_carpamaCA);

        final CRLEntries emptyEntries = test04_consterCA.new CRLEntries();
        X509CRL consterCRL = test04_consterCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 7 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 17 * ONE_HOUR_IN_MS),
                new BigInteger("5"),
                emptyEntries );
        X509CRL ascendeusCRL = test04_ascendeusCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 2 * ONE_DAY_IN_MS),
                new Date(now.getTime() + 5 * ONE_DAY_IN_MS),
                new BigInteger("5"),
                emptyEntries);
        X509CRL ascendeusIssuingCRL = test04_ascendeusIssuingCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("5"),
                emptyEntries);
        X509CRL carpamaCRL = test04_carpamaCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 4 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 4 * ONE_HOUR_IN_MS),
                new BigInteger("5"),
                emptyEntries);
        Collection<X509CRL> tsaCRLs =createCRLCollection(
                consterCRL,
                ascendeusCRL,
                ascendeusIssuingCRL,
                carpamaCRL);
        CertStore tsaIntermCertsAndCrls = certStoreForCertsAndCrls(tsaCRLs,
                test04_consterCA.getCertificate(),
                test04_consterTSA17ya.getCertificate(),
                test04_ascendeusCA.getCertificate(),
                test04_ascendeusIssuingCA.getCertificate(),
                test04_ascendeusTSA17ya.getCertificate(),
                test04_ascendeusTSA13ya.getCertificate(),
                test04_carpamaCA.getCertificate(),
                test04_carpamaTSA13ya.getCertificate());
        TSACertificateValidationProvider tsaValidationDataProvider =
                new PKIXTSACertificateValidationProvider(
                        tsaTrustAnchors,
                        true,
                        tsaIntermCertsAndCrls);
        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        formExtProfile.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test04_certValidationDataProviderCCreation,
                        tsaValidationDataProvider);

        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().setDefaultVerificationDate(now);

        XAdESVerificationResult res = verifier.verify(signatureNode, options, formExt,
                XAdESForm.X);

        assertEquals(res.getSignatureForm(), XAdESForm.X);

        outputDocument(doc, "document.aged.test04.X2.xml");
    }

    // add certificates to signature (X-L form)
    @Test
    public void test04_06_XL_sig6() throws Exception
    {
        System.out.println("test04_XL_sig6");

        final Date now = new Date(realNow.getTime() - 13 * ONE_YEAR_IN_MS
                + 14 * ONE_DAY_IN_MS);
        final CRLEntries emptyEntries = test04_ascendeusCA.new CRLEntries();

        Document doc = getOutputDocument("document.aged.test04.X2.xml");
        Element signatureNode = getSigElement(doc);

        KeyStore tsaTrustAnchors = keyStoreForCerts(
                test04_ascendeusCA,
                test04_consterCA,
                test04_carpamaCA);
        X509CRL ascendeusCRL = test04_ascendeusCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 1 * ONE_DAY_IN_MS),
                new Date(now.getTime() + 6 * ONE_DAY_IN_MS),
                new BigInteger("6"),
                emptyEntries);
        X509CRL ascendeusIssuingCRL = test04_ascendeusIssuingCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("6"),
                emptyEntries);
        X509CRL consterCRL = test04_consterCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 20 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 1  * ONE_HOUR_IN_MS),
                new BigInteger("6"),
                emptyEntries);
        X509CRL carpamaCRL = test04_carpamaCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 4 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 20 * ONE_HOUR_IN_MS),
                new BigInteger("6"),
                emptyEntries);
        Collection<X509CRL> tsaCRLs = createCRLCollection(
                ascendeusCRL,
                ascendeusIssuingCRL,
                consterCRL,
                carpamaCRL);
        CertStore tsaIntermCertsAndCrls = certStoreForCertsAndCrls(tsaCRLs,
                test04_ascendeusCA.getCertificate(),
                test04_ascendeusIssuingCA.getCertificate(),
                test04_ascendeusTSA17ya.getCertificate(),
                test04_ascendeusTSA13ya.getCertificate(),
                test04_consterCA.getCertificate(),
                test04_consterTSA17ya.getCertificate(),
                test04_carpamaCA.getCertificate(),
                test04_carpamaTSA13ya.getCertificate());
        TSACertificateValidationProvider tsaValidationDataProvider =
                new PKIXTSACertificateValidationProvider(tsaTrustAnchors,
                        true,
                        tsaIntermCertsAndCrls);

        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        // it shouldn't be used now, as it is not configured, it will throw an exception
        formExtProfile.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test04_certValidationDataProviderCCreation,
                        tsaValidationDataProvider);

        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().setDefaultVerificationDate(now);

        XAdESVerificationResult res = verifier.verify(signatureNode, options, formExt,
                XAdESForm.X_L);

        assertEquals(res.getSignatureForm(), XAdESForm.X);

        outputDocument(doc, "document.aged.test04.XL.xml");
    }

    // add first Archival Time Stamp
    @Test
    public void test04_07_A_sig7() throws Exception
    {
        System.out.println("test04_A_sig7");
        Date now = new Date(realNow.getTime() - 9 * ONE_YEAR_IN_MS);
        SurrogateTimeStampTokenProvider.setTSACert(test04_carpamaTSA9ya);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(now, new BigInteger("37"));

        Document doc = getOutputDocument("document.aged.test04.XL.xml");
        Element signatureNode = getSigElement(doc);
        KeyStore tsaTrustAnchors = keyStoreForCerts(
                test04_consterCA,
                test04_ascendeusCA,
                test04_carpamaCA,
                test04_premoxCA);

        final CRLEntries emptyEntries = test04_consterCA.new CRLEntries();
        X509CRL ascendeusCRL = test04_ascendeusCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 2 * ONE_DAY_IN_MS),
                new Date(now.getTime() + 5 * ONE_DAY_IN_MS),
                new BigInteger("7"),
                emptyEntries);
        X509CRL ascendeusIssuingCRL = test04_ascendeusIssuingCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("7"),
                emptyEntries);
        X509CRL carpamaCRL = test04_carpamaCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 4 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 4 * ONE_HOUR_IN_MS),
                new BigInteger("7"),
                emptyEntries);
        X509CRL premoxCRL = test04_premoxCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("7"),
                emptyEntries);
        Collection<X509CRL> tsaCRLs =createCRLCollection(
                ascendeusCRL,
                ascendeusIssuingCRL,
                carpamaCRL,
                premoxCRL);
        CertStore tsaIntermCertsAndCrls = certStoreForCertsAndCrls(tsaCRLs,
                test04_ascendeusCA.getCertificate(),
                test04_ascendeusIssuingCA.getCertificate(),
                test04_ascendeusTSA13ya.getCertificate(),
                test04_carpamaCA.getCertificate(),
                test04_carpamaTSA13ya.getCertificate(),
                test04_carpamaTSA9ya.getCertificate(),
                test04_premoxCA.getCertificate(),
                test04_premoxTSA9ya.getCertificate());
        TSACertificateValidationProvider tsaValidationDataProvider =
                new PKIXTSACertificateValidationProvider(
                        tsaTrustAnchors,
                        true,
                        tsaIntermCertsAndCrls);
        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        formExtProfile.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test04_certValidationDataProviderOnlyTrustAnchors,
                        tsaValidationDataProvider);

        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().setDefaultVerificationDate(now);

        XAdESVerificationResult res = verifier.verify(signatureNode, options, formExt,
                XAdESForm.A);

        assertEquals(res.getSignatureForm(), XAdESForm.X_L);

        outputDocument(doc, "document.aged.test04.A.xml");
    }

    // add second Archival time stamp
    @Test
    public void test04_08_A_sig8() throws Exception
    {
        System.out.println("test04_A_sig8");
        Date now = new Date(realNow.getTime() - 9 * ONE_YEAR_IN_MS + ONE_HOUR_IN_MS / 60);
        SurrogateTimeStampTokenProvider.setTSACert(test04_premoxTSA9ya);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(
                now,
                new BigInteger("38"));

        Document doc = getOutputDocument("document.aged.test04.A.xml");
        Element signatureNode = getSigElement(doc);
        KeyStore tsaTrustAnchors = keyStoreForCerts(
                test04_consterCA,
                test04_ascendeusCA,
                test04_carpamaCA,
                test04_premoxCA);

        final CRLEntries emptyEntries = test04_consterCA.new CRLEntries();
        X509CRL ascendeusCRL = test04_ascendeusCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 2 * ONE_DAY_IN_MS),
                new Date(now.getTime() + 5 * ONE_DAY_IN_MS),
                new BigInteger("8"),
                emptyEntries);
        X509CRL ascendeusIssuingCRL = test04_ascendeusIssuingCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("8"),
                emptyEntries);
        X509CRL carpamaCRL = test04_carpamaCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 4 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 4 * ONE_HOUR_IN_MS),
                new BigInteger("8"),
                emptyEntries);
        X509CRL premoxCRL = test04_premoxCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("8"),
                emptyEntries);
        Collection<X509CRL> tsaCRLs =createCRLCollection(
                ascendeusCRL,
                ascendeusIssuingCRL,
                carpamaCRL,
                premoxCRL);
        CertStore tsaIntermCertsAndCrls = certStoreForCertsAndCrls(tsaCRLs,
                test04_ascendeusCA.getCertificate(),
                test04_ascendeusIssuingCA.getCertificate(),
                test04_ascendeusTSA13ya.getCertificate(),
                test04_carpamaCA.getCertificate(),
                test04_carpamaTSA13ya.getCertificate(),
                test04_carpamaTSA9ya.getCertificate(),
                test04_premoxCA.getCertificate(),
                test04_premoxTSA9ya.getCertificate());
        TSACertificateValidationProvider tsaValidationDataProvider =
                new PKIXTSACertificateValidationProvider(
                        tsaTrustAnchors,
                        true,
                        tsaIntermCertsAndCrls);
        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        formExtProfile.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test04_certValidationDataProviderOnlyTrustAnchors,
                        tsaValidationDataProvider);

        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().setDefaultVerificationDate(now);

        XAdESVerificationResult res = verifier.verify(signatureNode, options, formExt,
                XAdESForm.A);

        assertEquals(XAdESForm.A, res.getSignatureForm());

        outputDocument(doc, "document.aged.test04.A2.xml");
    }

    @Test
    public void test04_09_AVD_sig9() throws Exception
    {
        System.out.println("test04_AVD_sig9");

        final Date now = new Date(realNow.getTime() - 9 * ONE_YEAR_IN_MS
                + 14 * ONE_DAY_IN_MS);
        final CRLEntries emptyEntries = test04_ascendeusCA.new CRLEntries();

        Document doc = getOutputDocument("document.aged.test04.A2.xml");
        Element signatureNode = getSigElement(doc);

        KeyStore tsaTrustAnchors = keyStoreForCerts(
                test04_consterCA,
                test04_ascendeusCA,
                test04_carpamaCA,
                test04_premoxCA);
        X509CRL ascendeusCRL = test04_ascendeusCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 1 * ONE_DAY_IN_MS),
                new Date(now.getTime() + 6 * ONE_DAY_IN_MS),
                new BigInteger("9"),
                emptyEntries);
        X509CRL ascendeusIssuingCRL = test04_ascendeusIssuingCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("9"),
                emptyEntries);
        X509CRL carpamaCRL = test04_carpamaCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 4 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 20 * ONE_HOUR_IN_MS),
                new BigInteger("9"),
                emptyEntries);
        X509CRL premoxCRL = test04_premoxCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("9"),
                emptyEntries);
        Collection<X509CRL> tsaCRLs = createCRLCollection(
                ascendeusCRL,
                ascendeusIssuingCRL,
                premoxCRL,
                carpamaCRL);
        CertStore tsaIntermCertsAndCrls = certStoreForCertsAndCrls(tsaCRLs,
                test04_ascendeusCA.getCertificate(),
                test04_ascendeusIssuingCA.getCertificate(),
                test04_ascendeusTSA13ya.getCertificate(),
                test04_carpamaCA.getCertificate(),
                test04_carpamaTSA13ya.getCertificate(),
                test04_carpamaTSA9ya.getCertificate(),
                test04_premoxCA.getCertificate(),
                test04_premoxTSA9ya.getCertificate());
        TSACertificateValidationProvider tsaValidationDataProvider =
                new PKIXTSACertificateValidationProvider(tsaTrustAnchors,
                        true,
                        tsaIntermCertsAndCrls);

        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        // it shouldn't be used now, as it is not configured, it will throw an exception
        formExtProfile.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test04_certValidationDataProviderOnlyTrustAnchors,
                        tsaValidationDataProvider);

        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().setDefaultVerificationDate(now);

        XAdESVerificationResult res = verifier.verify(signatureNode, options, formExt,
                XAdESForm.A_VD);

        assertEquals(res.getSignatureForm(), XAdESForm.A);

        outputDocument(doc, "document.aged.test04.AVD.xml");
    }

    // add second group of A time stamps
    @Test
    public void test04_10_2A_sig10() throws Exception
    {
        System.out.println("test04_2A_sig10");
        Date now = new Date(realNow.getTime() - 5 * ONE_YEAR_IN_MS);
        SurrogateTimeStampTokenProvider.setTSACert(test04_premoxTSA5ya);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(now, new BigInteger("38"));

        Document doc = getOutputDocument("document.aged.test04.AVD.xml");
        Element signatureNode = getSigElement(doc);
        KeyStore tsaTrustAnchors = keyStoreForCerts(
                test04_consterCA,
                test04_ascendeusCA,
                test04_carpamaCA,
                test04_premoxCA,
                test04_gescapeCA);

        final CRLEntries emptyEntries = test04_consterCA.new CRLEntries();
        X509CRL gescapeCRL = test04_gescapeCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 2 * ONE_DAY_IN_MS),
                new Date(now.getTime() + 5 * ONE_DAY_IN_MS),
                new BigInteger("10"),
                emptyEntries);
        X509CRL carpamaCRL = test04_carpamaCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 4 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 4 * ONE_HOUR_IN_MS),
                new BigInteger("10"),
                emptyEntries);
        X509CRL premoxCRL = test04_premoxCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("10"),
                emptyEntries);
        Collection<X509CRL> tsaCRLs = createCRLCollection(
                carpamaCRL,
                premoxCRL,
                gescapeCRL);
        CertStore tsaIntermCertsAndCrls = certStoreForCertsAndCrls(tsaCRLs,
                test04_gescapeCA.getCertificate(),
                test04_gescapeTSA5ya.getCertificate(),
                test04_carpamaCA.getCertificate(),
                test04_carpamaTSA9ya.getCertificate(),
                test04_premoxCA.getCertificate(),
                test04_premoxTSA9ya.getCertificate(),
                test04_premoxTSA5ya.getCertificate());
        TSACertificateValidationProvider tsaValidationDataProvider =
                new PKIXTSACertificateValidationProvider(
                        tsaTrustAnchors,
                        true,
                        tsaIntermCertsAndCrls);
        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        formExtProfile.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test04_certValidationDataProviderOnlyTrustAnchors,
                        tsaValidationDataProvider);

        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().setDefaultVerificationDate(now);

        XAdESVerificationResult res = verifier.verify(signatureNode, options, formExt,
                XAdESForm.A);

        assertEquals(res.getSignatureForm(), XAdESForm.A);

        outputDocument(doc, "document.aged.test04.2A.xml");
    }

    // add second time stamp in second group of timestamps
    @Test
    public void test04_11_2A_sig11() throws Exception
    {
        System.out.println("test04_2A_sig11");
        Date now = new Date(realNow.getTime() - 5 * ONE_YEAR_IN_MS + ONE_HOUR_IN_MS);
        SurrogateTimeStampTokenProvider.setTSACert(test04_gescapeTSA5ya);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(now, new BigInteger("39"));

        Document doc = getOutputDocument("document.aged.test04.2A.xml");
        Element signatureNode = getSigElement(doc);
        KeyStore tsaTrustAnchors = keyStoreForCerts(
                test04_consterCA,
                test04_ascendeusCA,
                test04_carpamaCA,
                test04_premoxCA,
                test04_gescapeCA);

        final CRLEntries emptyEntries = test04_consterCA.new CRLEntries();
        X509CRL gescapeCRL = test04_gescapeCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 2 * ONE_DAY_IN_MS),
                new Date(now.getTime() + 5 * ONE_DAY_IN_MS),
                new BigInteger("11"),
                emptyEntries);
        X509CRL carpamaCRL = test04_carpamaCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 4 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 4 * ONE_HOUR_IN_MS),
                new BigInteger("11"),
                emptyEntries);
        X509CRL premoxCRL = test04_premoxCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("11"),
                emptyEntries);
        Collection<X509CRL> tsaCRLs = createCRLCollection(
                carpamaCRL,
                premoxCRL,
                gescapeCRL);
        CertStore tsaIntermCertsAndCrls = certStoreForCertsAndCrls(tsaCRLs,
                test04_gescapeCA.getCertificate(),
                test04_gescapeTSA5ya.getCertificate(),
                test04_carpamaCA.getCertificate(),
                test04_carpamaTSA9ya.getCertificate(),
                test04_premoxCA.getCertificate(),
                test04_premoxTSA9ya.getCertificate(),
                test04_premoxTSA5ya.getCertificate());
        TSACertificateValidationProvider tsaValidationDataProvider =
                new PKIXTSACertificateValidationProvider(
                        tsaTrustAnchors,
                        true,
                        tsaIntermCertsAndCrls);
        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        formExtProfile.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test04_certValidationDataProviderOnlyTrustAnchors,
                        tsaValidationDataProvider);

        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().setDefaultVerificationDate(now);

        XAdESVerificationResult res = verifier.verify(signatureNode, options, formExt,
                XAdESForm.A);

        assertEquals(res.getSignatureForm(), XAdESForm.A);

        outputDocument(doc, "document.aged.test04.2A2.xml");
    }

    // add revocation information about first group of archive time stamps
    @Test
    public void test04_12_2AVD_sig12() throws Exception
    {
        System.out.println("test04_2AVD_sig12");

        final Date now = new Date(realNow.getTime() - 5 * ONE_YEAR_IN_MS
                + 14 * ONE_DAY_IN_MS);
        final CRLEntries emptyEntries = test04_ascendeusCA.new CRLEntries();

        Document doc = getOutputDocument("document.aged.test04.2A2.xml");
        Element signatureNode = getSigElement(doc);

        KeyStore tsaTrustAnchors = keyStoreForCerts(
                test04_consterCA,
                test04_ascendeusCA,
                test04_carpamaCA,
                test04_premoxCA,
                test04_gescapeCA);
        X509CRL carpamaCRL = test04_carpamaCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 4 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 20 * ONE_HOUR_IN_MS),
                new BigInteger("12"),
                emptyEntries);
        X509CRL premoxCRL = test04_premoxCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("12"),
                emptyEntries);
        X509CRL gescapeCRL = test04_gescapeCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("12"),
                emptyEntries);
        Collection<X509CRL> tsaCRLs = createCRLCollection(
                premoxCRL,
                carpamaCRL,
                gescapeCRL);
        CertStore tsaIntermCertsAndCrls = certStoreForCertsAndCrls(tsaCRLs,
                test04_carpamaCA.getCertificate(),
                test04_carpamaTSA9ya.getCertificate(),
                test04_premoxCA.getCertificate(),
                test04_premoxTSA9ya.getCertificate(),
                test04_gescapeCA.getCertificate(),
                test04_gescapeTSA5ya.getCertificate(),
                test04_premoxTSA5ya.getCertificate());
        TSACertificateValidationProvider tsaValidationDataProvider =
                new PKIXTSACertificateValidationProvider(tsaTrustAnchors,
                        true,
                        tsaIntermCertsAndCrls);

        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        // it shouldn't be used now, as it is not configured, it will throw an exception
        formExtProfile.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test04_certValidationDataProviderOnlyTrustAnchors,
                        tsaValidationDataProvider);

        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().setDefaultVerificationDate(now);

        XAdESVerificationResult res = verifier.verify(signatureNode, options, formExt,
                XAdESForm.A_VD);

        assertEquals(res.getSignatureForm(), XAdESForm.A);

        outputDocument(doc, "document.aged.test04.2AVD.xml");
    }

    // add first timestamp to third group of timestamps
    @Test
    public void test04_13_3A_sig13() throws Exception
    {
        System.out.println("test04_3A_sig13");
        Date now = new Date(realNow.getTime() - 1 * ONE_YEAR_IN_MS);
        SurrogateTimeStampTokenProvider.setTSACert(test04_unibimTSA1ya);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(now, new BigInteger("39"));

        Document doc = getOutputDocument("document.aged.test04.2AVD.xml");
        Element signatureNode = getSigElement(doc);
        KeyStore tsaTrustAnchors = keyStoreForCerts(
                test04_consterCA,
                test04_ascendeusCA,
                test04_carpamaCA,
                test04_premoxCA,
                test04_gescapeCA,
                test04_unibimCA);

        final CRLEntries emptyEntries = test04_consterCA.new CRLEntries();
        X509CRL gescapeCRL = test04_gescapeCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 2 * ONE_DAY_IN_MS),
                new Date(now.getTime() + 5 * ONE_DAY_IN_MS),
                new BigInteger("13"),
                emptyEntries);
        X509CRL premoxCRL = test04_premoxCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("13"),
                emptyEntries);
        X509CRL unibimCRL = test04_unibimCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("13"),
                emptyEntries);
        Collection<X509CRL> tsaCRLs = createCRLCollection(
                premoxCRL,
                gescapeCRL,
                unibimCRL);
        CertStore tsaIntermCertsAndCrls = certStoreForCertsAndCrls(tsaCRLs,
                test04_gescapeCA.getCertificate(),
                test04_gescapeTSA5ya.getCertificate(),
                test04_premoxCA.getCertificate(),
                test04_premoxTSA5ya.getCertificate(),
                test04_unibimCA.getCertificate(),
                test04_unibimTSA1ya.getCertificate());
        TSACertificateValidationProvider tsaValidationDataProvider =
                new PKIXTSACertificateValidationProvider(
                        tsaTrustAnchors,
                        true,
                        tsaIntermCertsAndCrls);
        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        formExtProfile.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test04_certValidationDataProviderOnlyTrustAnchors,
                        tsaValidationDataProvider);

        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().setDefaultVerificationDate(now);

        XAdESVerificationResult res = verifier.verify(signatureNode, options, formExt,
                XAdESForm.A);

        assertEquals(res.getSignatureForm(), XAdESForm.A);

        outputDocument(doc, "document.aged.test04.3A.xml");
    }

    // add second timestamp to third group of timestamps
    @Test
    public void test04_14_3A_sig14() throws Exception
    {
        System.out.println("test04_3A_sig14");
        Date now = new Date(realNow.getTime() - 1 * ONE_YEAR_IN_MS + ONE_HOUR_IN_MS);
        SurrogateTimeStampTokenProvider.setTSACert(test04_astronTSA1ya);
        SurrogateTimeStampTokenProvider.setTimeAndSerial(now, new BigInteger("40"));

        Document doc = getOutputDocument("document.aged.test04.3A.xml");
        Element signatureNode = getSigElement(doc);
        KeyStore tsaTrustAnchors = keyStoreForCerts(
                test04_consterCA,
                test04_ascendeusCA,
                test04_carpamaCA,
                test04_premoxCA,
                test04_gescapeCA,
                test04_unibimCA,
                test04_astronCA);

        final CRLEntries emptyEntries = test04_consterCA.new CRLEntries();
        X509CRL gescapeCRL = test04_gescapeCA.createCRL(
                "SHA1withRSA",
                new Date(now.getTime() - 2 * ONE_DAY_IN_MS),
                new Date(now.getTime() + 5 * ONE_DAY_IN_MS),
                new BigInteger("14"),
                emptyEntries);
        X509CRL premoxCRL = test04_premoxCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("14"),
                emptyEntries);
        X509CRL unibimCRL = test04_unibimCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("14"),
                emptyEntries);
        X509CRL astronCRL = test04_astronCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("14"),
                emptyEntries);
        Collection<X509CRL> tsaCRLs = createCRLCollection(
                premoxCRL,
                gescapeCRL,
                unibimCRL,
                astronCRL);
        CertStore tsaIntermCertsAndCrls = certStoreForCertsAndCrls(tsaCRLs,
                test04_gescapeCA.getCertificate(),
                test04_gescapeTSA5ya.getCertificate(),
                test04_premoxCA.getCertificate(),
                test04_premoxTSA5ya.getCertificate(),
                test04_unibimCA.getCertificate(),
                test04_unibimTSA1ya.getCertificate());
        TSACertificateValidationProvider tsaValidationDataProvider =
                new PKIXTSACertificateValidationProvider(
                        tsaTrustAnchors,
                        true,
                        tsaIntermCertsAndCrls);
        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        formExtProfile.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test04_certValidationDataProviderOnlyTrustAnchors,
                        tsaValidationDataProvider);

        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().setDefaultVerificationDate(now);

        XAdESVerificationResult res = verifier.verify(signatureNode, options, formExt,
                XAdESForm.A);

        assertEquals(res.getSignatureForm(), XAdESForm.A);

        outputDocument(doc, "document.aged.test04.3A2.xml");
    }

    // add revocation information about second group of archive time stamps
    @Test
    public void test04_15_3AVD_sig15() throws Exception
    {
        System.out.println("test04_3AVD_sig14");

        final Date now = new Date(realNow.getTime() - 1 * ONE_YEAR_IN_MS
                + 14 * ONE_DAY_IN_MS);
        final CRLEntries emptyEntries = test04_ascendeusCA.new CRLEntries();

        Document doc = getOutputDocument("document.aged.test04.3A2.xml");
        Element signatureNode = getSigElement(doc);

        KeyStore tsaTrustAnchors = keyStoreForCerts(
                test04_consterCA,
                test04_ascendeusCA,
                test04_carpamaCA,
                test04_premoxCA,
                test04_gescapeCA,
                test04_unibimCA,
                test04_astronCA);
        X509CRL premoxCRL = test04_premoxCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("14"),
                emptyEntries);
        X509CRL gescapeCRL = test04_gescapeCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("14"),
                emptyEntries);
        X509CRL unibimCRL = test04_unibimCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("14"),
                emptyEntries);
        X509CRL astronCRL = test04_astronCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("14"),
                emptyEntries);
        Collection<X509CRL> tsaCRLs = createCRLCollection(
                premoxCRL,
                gescapeCRL,
                unibimCRL,
                astronCRL);
        CertStore tsaIntermCertsAndCrls = certStoreForCertsAndCrls(tsaCRLs,
                test04_premoxCA.getCertificate(),
                test04_premoxTSA5ya.getCertificate(),
                test04_gescapeCA.getCertificate(),
                test04_gescapeTSA5ya.getCertificate(),
                test04_unibimCA.getCertificate(),
                test04_unibimTSA1ya.getCertificate(),
                test04_astronCA.getCertificate(),
                test04_astronTSA1ya.getCertificate());
        TSACertificateValidationProvider tsaValidationDataProvider =
                new PKIXTSACertificateValidationProvider(tsaTrustAnchors,
                        true,
                        tsaIntermCertsAndCrls);

        XadesFormatExtenderProfile formExtProfile = new XadesFormatExtenderProfile();
        // it shouldn't be used now, as it is not configured, it will throw an exception
        formExtProfile.withTimeStampTokenProvider(SurrogateTimeStampTokenProvider.class);
        XadesSignatureFormatExtender formExt = formExtProfile.getFormatExtender();
        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test04_certValidationDataProviderOnlyTrustAnchors,
                        tsaValidationDataProvider);

        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().setDefaultVerificationDate(now);

        XAdESVerificationResult res = verifier.verify(signatureNode, options, formExt,
                XAdESForm.A_VD);

        assertEquals(res.getSignatureForm(), XAdESForm.A);

        outputDocument(doc, "document.aged.test04.3AVD.xml");
    }

    // test with minimal revocation information and all trust anchors
    @Test
    public void test04_16_3AVD_ver1() throws Exception
    {
        System.out.println("test04_3AVD_ver1");

        final Date now = realNow;
        final CRLEntries emptyEntries = test04_ascendeusCA.new CRLEntries();

        Document doc = getOutputDocument("document.aged.test04.3AVD.xml");
        Element signatureNode = getSigElement(doc);

        KeyStore tsaTrustAnchors = keyStoreForCerts(
                test04_consterCA,
                test04_ascendeusCA,
                test04_carpamaCA,
                test04_premoxCA,
                test04_gescapeCA,
                test04_unibimCA,
                test04_astronCA);
        X509CRL unibimCRL = test04_unibimCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("14"),
                emptyEntries);
        X509CRL astronCRL = test04_astronCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("14"),
                emptyEntries);
        Collection<X509CRL> tsaCRLs = createCRLCollection(
                unibimCRL,
                astronCRL);
        CertStore tsaIntermCertsAndCrls = certStoreForCertsAndCrls(tsaCRLs,
                test04_unibimCA.getCertificate(),
                test04_astronCA.getCertificate());
        TSACertificateValidationProvider tsaValidationDataProvider =
                new PKIXTSACertificateValidationProvider(tsaTrustAnchors,
                        true,
                        tsaIntermCertsAndCrls);

        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test04_certValidationDataProviderOnlyTrustAnchors,
                        tsaValidationDataProvider);

        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();

        XAdESVerificationResult res = verifier.verify(signatureNode, null);

        assertEquals(res.getSignatureForm(), XAdESForm.A);
    }

    // test with minimal revocation information and only some TSA trust anchors (minimal amount
    // that will still allow for successful history traversal)
    @Test
    public void test04_17_3AVD_ver2() throws Exception
    {
        System.out.println("test04_3AVD_ver2");

        final Date now = realNow;
        final CRLEntries emptyEntries = test04_ascendeusCA.new CRLEntries();

        Document doc = getOutputDocument("document.aged.test04.3AVD.xml");
        Element signatureNode = getSigElement(doc);

        KeyStore tsaTrustAnchors = keyStoreForCerts(
                test04_consterCA,
                test04_carpamaCA,
                test04_gescapeCA,
                test04_astronCA);
        X509CRL astronCRL = test04_astronCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("14"),
                emptyEntries);
        Collection<X509CRL> tsaCRLs = createCRLCollection(
                astronCRL);
        CertStore tsaIntermCertsAndCrls = certStoreForCertsAndCrls(tsaCRLs,
                test04_astronCA.getCertificate());
        TSACertificateValidationProvider tsaValidationDataProvider =
                new PKIXTSACertificateValidationProvider(tsaTrustAnchors,
                        true,
                        tsaIntermCertsAndCrls);

        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test04_certValidationDataProviderOnlyTrustAnchors,
                        tsaValidationDataProvider);

        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();

        XAdESVerificationResult res = verifier.verify(signatureNode, null);

        assertEquals(res.getSignatureForm(), XAdESForm.A);
    }

    // test with minimal revocation information and only some TSA trust anchors
    // removal of trust for all newest TSAs (gescape TSA is valid but don't provide CRL
    // for it)
    @Test(expected = CannotBuildCertificationPathException.class)
    public void test04_18_3AVD_ver3() throws Exception
    {
        System.out.println("test04_3AVD_ver3");

        final Date now = realNow;
        final CRLEntries emptyEntries = test04_ascendeusCA.new CRLEntries();

        Document doc = getOutputDocument("document.aged.test04.3AVD.xml");
        Element signatureNode = getSigElement(doc);

        KeyStore tsaTrustAnchors = keyStoreForCerts(
                test04_consterCA,
                test04_carpamaCA,
                test04_gescapeCA);
        X509CRL astronCRL = test04_astronCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("14"),
                emptyEntries);
        Collection<X509CRL> tsaCRLs = createCRLCollection(
                astronCRL);
        CertStore tsaIntermCertsAndCrls = certStoreForCertsAndCrls(tsaCRLs,
                test04_astronCA.getCertificate());
        TSACertificateValidationProvider tsaValidationDataProvider =
                new PKIXTSACertificateValidationProvider(tsaTrustAnchors,
                        true,
                        tsaIntermCertsAndCrls);

        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test04_certValidationDataProviderOnlyTrustAnchors,
                        tsaValidationDataProvider);

        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();

        XAdESVerificationResult res = verifier.verify(signatureNode, null);

        assertEquals(res.getSignatureForm(), XAdESForm.A);
    }

    // test with minimal revocation information and only some TSA trust anchors
    // removal of trust for all newest TSAs, but provide CRL for gescape
    @Test
    public void test04_19_3AVD_ver4() throws Exception
    {
        System.out.println("test04_3AVD_ver3");

        final Date now = realNow;
        final CRLEntries emptyEntries = test04_ascendeusCA.new CRLEntries();

        Document doc = getOutputDocument("document.aged.test04.3AVD.xml");
        Element signatureNode = getSigElement(doc);

        KeyStore tsaTrustAnchors = keyStoreForCerts(
                test04_consterCA,
                test04_carpamaCA,
                test04_gescapeCA);
        X509CRL gescapeCRL = test04_gescapeCA.createCRL(
                "SHA256withRSA",
                new Date(now.getTime() - 12 * ONE_HOUR_IN_MS),
                new Date(now.getTime() + 12 * ONE_HOUR_IN_MS),
                new BigInteger("14"),
                emptyEntries);
        Collection<X509CRL> tsaCRLs = createCRLCollection(
                gescapeCRL);
        CertStore tsaIntermCertsAndCrls = certStoreForCertsAndCrls(tsaCRLs,
                test04_gescapeCA.getCertificate());
        TSACertificateValidationProvider tsaValidationDataProvider =
                new PKIXTSACertificateValidationProvider(tsaTrustAnchors,
                        true,
                        tsaIntermCertsAndCrls);

        XadesVerificationProfile verProfile = new XadesVerificationProfile(
                        test04_certValidationDataProviderOnlyTrustAnchors,
                        tsaValidationDataProvider);

        XadesHybridVerifierImpl verifier = (XadesHybridVerifierImpl) verProfile.newVerifier();

        XAdESVerificationResult res = verifier.verify(signatureNode, null);

        assertEquals(res.getSignatureForm(), XAdESForm.A);
    }

    /*
     * TODO missing grace period support
     * The library should support enforcing grace period, but what's more important, it
     * should add only necessary CRLs when creating revocation information related
     * properties. If that's not performed, then CRLs that don't help in later
     * validation will be added causing the file size to grow needlessly.

  time
    .
    |   <- Signature creation time
    |
    |   <- SignatureTimeStamp creation time (XAdES-T)
    | +
    | |
    | | grace period for Signature
    | |
    | +
    |   <- earliest time a CRL will make the Signature non-repudiable
    |
    |   <- publishing of CRL for Signature certificate
    |   <- earliest time a usable XAdES-C can be created
    /
    /
    |   <- SigAndRefsTimeStamp creation time (XAdES-X)
    | +
    | |
    | | grace period for SignatureTimeStamp
    | |
    | +
    |   <- earliest time a CRL will make SignatureTimeStamp non-repudiable
    |
    |   <- publishing of CRL for SignatureTimeStamp certificate
    |   <- earliest time a usable XAdES-X-L can be created
    /
    /
    |   <- 1st ArchiveTimeStamp creation time (XAdES-A)
    | +
    | |
    | | grace period for SigAndRefsTimeSamp
    | |
    | +
    |  <- earliest time a CRL will make SigAndRefsTimeStamp non-repudiable
    |
    |  <- publishing of CRL for SigAndRefsTimeStamp
    |  <- earliest time TimeStampValidationData can be created (XAdES-A-VD)
    /
    /
    |  <- 2nd ArchiveTimeStamp creation time (XAdES-A)
    | +
    | |
    | | grace period for 1st ArchiveTimeStamp
    | |
    | +
    |  <- earliest time a CRL will make 1st ArchiveTimeStamp non-repudiable
    |
    |  <- publishing of CRL for 1st ArchiveTimeStamp
    |  <- earliest time TimeStampValidationData for 1st ArchiveTimeStamp can be created
    '

     */
    /*
     * end of tests
     */

    // helper method
    private XAdESForm verifySignature(String path,
            XadesVerificationProfile p)
            throws FileNotFoundException, ParserConfigurationException,
            SAXException, IOException, XadesProfileResolutionException, XAdES4jException
    {
        Element signatureNode = getSigElement(getOutputDocument(path));
        XAdESVerificationResult res = p.newVerifier().verify(signatureNode, null);
        return res.getSignatureForm();
    }

    // helper method
    private Element getSigElement(Document document)
    {
        return (Element)document.getElementsByTagNameNS(Constants.SignatureSpecNS,
                Constants._TAG_SIGNATURE).item(0);
    }

    private void removeFile(String path)
    {
        File outDir = ensureOutputDir("xml/");
        File file = new File(outDir, path);
        file.delete();
    }

    // helper method
    private void outputDocument(Document doc, String fileName) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        File outDir = ensureOutputDir("xml");
        FileOutputStream out = new FileOutputStream(new File(outDir, fileName));
        tf.newTransformer().transform(
                new DOMSource(doc),
                new StreamResult(out));
        out.flush();
        out.getFD().sync();
        out.close();
    }

    private static File ensureOutputDir(String subdir) {
        File dir = new File(toPlatformSpecificFilePath("./target/out/" + subdir));
        dir.mkdirs();
        return dir;
    }

    /*private void outputDocument(Document doc, String path)
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
    }*/

    // helper method
    private static void saveCRL(String fileName, X509CRL crl)
            throws CRLException, IOException
    {
        File directory = ensureOutputDir("cert/aged");
        FileOutputStream fos = new FileOutputStream(new File(directory, fileName));
        fos.write(crl.getEncoded());
        fos.close();
        return;
    }

    // helper method
    /*private String toDocumentDirFilePath(String path)
    {
        return "./src/test/xml/" + path;
    }*/

    // helper method
    private static void saveCertificate(String fileName, X509Certificate cert)
            throws CertificateEncodingException, IOException
    {
        File outDir = ensureOutputDir("cert/aged");
        FileOutputStream fos = new FileOutputStream(new File(outDir, fileName));
        fos.write(cert.getEncoded());
        fos.close();
        return;
    }

    // helper method
    private Document getDocument(String fileName) throws ParserConfigurationException,
            FileNotFoundException, SAXException, IOException
    {
        String path = toPlatformSpecificXMLDirFilePath(fileName);
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new FileInputStream(path));
        Element elem = doc.getDocumentElement();
        DOMHelper.useIdAsXmlId(elem);
        return doc;
    }

    private Document getOutputDocument(String fileName) throws ParserConfigurationException,
            FileNotFoundException, SAXException, IOException {
        File outDir = ensureOutputDir("xml");
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new FileInputStream(new File(outDir, fileName)));
        Element elem = doc.getDocumentElement();
        DOMHelper.useIdAsXmlId(elem);
        return doc;
    }

    private static Collection<X509CRL> createCRLCollection(X509CRL... crls)
    {
        Collection<X509CRL> list = new ArrayList<X509CRL>(crls.length);
        for (X509CRL c : crls)
        {
            list.add(c);
        }
        return list;
    }

    private static CertStore certStoreForCertsAndCrls(Collection<X509CRL> crls,
            X509Certificate... certificates)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException
    {
        Collection<Object> certs = new ArrayList<Object>(crls.size() + certificates.length);
        for (X509Certificate cert : certificates)
        {
            certs.add(cert);
        }
        certs.addAll(crls);
        CertStore certStore = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(certs));
        return certStore;
    }

    private static KeyStore keyStoreForCerts(FullCert... certs) throws KeyStoreException,
            IOException, NoSuchAlgorithmException, CertificateException
    {
        KeyStore trustAnchors = KeyStore.getInstance(KeyStore.getDefaultType());
        trustAnchors.load(null);
        int i = 1;
        for(FullCert cert: certs)
        {
            Entry entry = new TrustedCertificateEntry(cert.getCertificate());
            trustAnchors.setEntry("ca" + i, entry , null);
            i++;
        }
        return trustAnchors;
    }
}
