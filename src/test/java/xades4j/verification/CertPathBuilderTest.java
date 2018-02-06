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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.Security;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.x509.ExtendedPKIXParameters;
import org.junit.Test;
import static xades4j.utils.SignatureServicesTestBase.toPlatformSpecificFilePath;

import xades4j.verification.FullCert.CRLEntries;

public class CertPathBuilderTest
{
    private static FullCert caCert;
    private static FullCert userCert;
    private static FullCert user2Cert;
    private static KeyStore trustAnchors;
    static
    {
        try {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        caCert = FullCert.getCACert("RSA", 1024, "CN=XAdES4j Testing CA",
                new Date(new Date().getTime() - 1000*60*60),
                new Date(new Date().getTime() + 1000*60*60),
                "SHA256withRSA"); /* cert will have serial number: 1 */
        saveCertificate("ca.cer", caCert.getCertificate());

        userCert = caCert.createUserCert("RSA", 1024, "CN=User Certificate",
                new Date(new Date().getTime() - 1000*60*60),
                new Date(new Date().getTime() + 1000*60*30),
                new BigInteger("2"), "SHA256withRSA");
        saveCertificate("user.cer", userCert.getCertificate());

        user2Cert = caCert.createTSACert("RSA", 1024, "CN=User 2 Certificate",
                new Date(new Date().getTime() - 1000*60*60),
                new Date(new Date().getTime() - 1000*60*30),
                new BigInteger("3"), "SHA256withRSA");
        saveCertificate("user2.cer", user2Cert.getCertificate());

        trustAnchors = KeyStore.getInstance(KeyStore.getDefaultType());
        trustAnchors.load(null, null);
        Entry caEntry = new TrustedCertificateEntry(caCert.getCertificate());
        trustAnchors.setEntry("ca", caEntry, null);

        } catch (Exception ex)
        {
            throw new RuntimeException("static initialization failed", ex);
        }
    }

    /*
     * Generator creates certificates with validity periods in the past:
     *
     * ^
     * | <-- in 1h:
     * |           caCert validity end
     * |
     * | <-- in 30 min:
     * |           userCert validity end
     * |
     * | <-- in 20 min:
     * |           CRL validity end (test1, test2)
     * |
     * | <-- *now*
     * |
     * | <- 1m ago:
     * |           CRL creation (test1, test2)
     * |
     * | <- 30 min ago:
     * |           user2Cert validity end
     * |
     * | <-- 45 min ago:
     * |           user2Cert validation
     * |
     * | <-- 1h ago:
     * |           caCert creation
     * |           userCert creation
     * |           user2Cert creation
     */

    /*
     * revoke certificate 1min ago, try to validate it before that (15min ago)
     * XXX fails with BC provider
     */
    @Test
    public void test1() throws Exception
    {
        System.out.println("test1");

        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX"/*, "BC"*/);

        X509CertSelector userCertSelector = new X509CertSelector();
        userCertSelector.setCertificate(userCert.getCertificate());

        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(trustAnchors, userCertSelector);

        // create CRL with user cert revoked after the time we will verify it at
        CRLEntries entries = caCert.new CRLEntries();
        entries.addEntry(userCert.getCertificate().getSerialNumber(),
                new Date(new Date().getTime() - 1000*60), CRLReason.unspecified);
        X509CRL crl = caCert.createCRL("SHA256withRSA",
                new Date(new Date().getTime() - 1000*60),
                new Date(new Date().getTime() + 1000*60*20),
                new BigInteger("3"),
                entries);
        saveCRL("test1.crl", crl);

        Collection<Object> content = new ArrayList<Object>();
        content.add(crl);
        content.add(userCert.getCertificate());
        //content.add(tsaCert.getCertificate());
        CertStore intermCertsAndCrls = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(content));

        buildParams.addCertStore(intermCertsAndCrls);
        buildParams.setRevocationEnabled(true);
        buildParams.setDate(new Date(new Date().getTime() - 1000*60*15));

        //ExtendedPKIXParameters extBuildParams = ExtendedPKIXParameters.getInstance(buildParams);
        //extBuildParams.setValidityModel(ExtendedPKIXParameters.PKIX_VALIDITY_MODEL);
        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(buildParams);
        CertPath certPath = result.getCertPath();

        System.out.println(certPath.getCertificates().get(0).getType());
    }

    /*
     * Try to validate certificate using CRL published after certificate validity end
     */
    @Test(expected = CertPathBuilderException.class)
    public void test2() throws Exception
    {
        System.out.println("test2");
        // test verification
        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");

        X509CertSelector userCertSelector = new X509CertSelector();
        userCertSelector.setCertificate(user2Cert.getCertificate());

        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(trustAnchors, userCertSelector);

        // create empty CRL
        CRLEntries entries = caCert.new CRLEntries();
        X509CRL crl = caCert.createCRL("SHA256withRSA",
                new Date(new Date().getTime() - 1000*60),
                new Date(new Date().getTime() + 1000*60*20),
                new BigInteger("3"),
                entries);
        saveCRL("test2.crl", crl);

        Collection<Object> content = new ArrayList<Object>();
        content.add(crl);
        content.add(user2Cert.getCertificate());
        //content.add(tsaCert.getCertificate());
        CertStore intermCertsAndCrls = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(content));

        buildParams.addCertStore(intermCertsAndCrls);
        buildParams.setRevocationEnabled(true);
        buildParams.setDate(new Date(new Date().getTime() - 1000*60*45)); // 45 minutes ago

        ExtendedPKIXParameters extBuildParams = ExtendedPKIXParameters.getInstance(buildParams);
        extBuildParams.setValidityModel(ExtendedPKIXParameters.PKIX_VALIDITY_MODEL);

        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(buildParams);
        CertPath certPath = result.getCertPath();

        System.out.println(certPath.getCertificates().get(0).getType());

    }

    /*
     * end of tests
     */
    private static File ensureOutputDir() {
        File dir = new File(toPlatformSpecificFilePath("./target/out/cert/certpath"));
        dir.mkdirs();
        return dir;
    }

    // helper method
    private static void saveCRL(String fileName, X509CRL crl)
            throws CRLException, IOException
    {
        File outDir = ensureOutputDir();
        FileOutputStream fos = new FileOutputStream(new File(outDir, fileName));
        fos.write(crl.getEncoded());
        fos.close();
        return;
    }

    // helper method
    private static void saveCertificate(String fileName, X509Certificate cert)
            throws CertificateEncodingException, IOException
    {
        File outDir = ensureOutputDir();
        FileOutputStream fos = new FileOutputStream(new File(outDir, fileName));
        fos.write(cert.getEncoded());
        fos.close();
        return;
    }
}
