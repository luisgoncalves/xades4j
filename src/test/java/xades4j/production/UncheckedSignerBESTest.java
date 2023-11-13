/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2021 achelos GmbH
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
package xades4j.production;

import org.apache.xml.security.utils.Constants;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.algorithms.ExclusiveCanonicalXMLWithoutComments;
import xades4j.properties.DataObjectDesc;
import xades4j.providers.CannotBuildCertificationPathException;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.utils.FileSystemDirectoryCertStore;
import xades4j.verification.SignatureSpecificVerificationOptions;
import xades4j.verification.SigningCertificateKeyUsageException;
import xades4j.verification.XAdESForm;
import xades4j.verification.XAdESVerificationResult;
import xades4j.verification.XadesVerificationProfile;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * This class test signing with the keyUsage check disabled.
 *
 * @author Fiona Klute
 */
class UncheckedSignerBESTest extends SignerTestBase
{
    private final KeyingDataProvider keyingProviderGood;
    private final KeyingDataProvider keyingProviderNoSign;
    private final KeyingDataProvider keyingProviderExp;
    private final KeyingDataProvider keyingProviderNyv;
    private final CertificateValidationProvider validationProvider;

    public UncheckedSignerBESTest() throws Exception
    {
        keyingProviderGood = createFileSystemKeyingDataProvider("PKCS12", "unchecked/good.p12", "password", true);
        keyingProviderNoSign = createFileSystemKeyingDataProvider("PKCS12", "unchecked/noSignKeyUsage.p12", "password", true);
        keyingProviderExp = createFileSystemKeyingDataProvider("PKCS12", "unchecked/expired.p12", "password", true);
        keyingProviderNyv = createFileSystemKeyingDataProvider("PKCS12", "unchecked/notYetValid.p12", "password", true);
        validationProvider = genValidationProvider("unchecked/TestCA.cer", "unchecked");
    }

    private void trySignAndVerify(final KeyingDataProvider signProvider,
                                  final CertificateValidationProvider verifyProvider, final String outputName) throws Exception
    {
        this.trySignAndVerify(signProvider, verifyProvider, outputName, true);
    }

    private void trySignAndVerify(final KeyingDataProvider signProvider,
                                  final CertificateValidationProvider verifyProvider, final String outputName,
                                  final boolean verifySignatureKeyUsage) throws Exception
    {
        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();

        final XadesBesSigningProfile signProfile = new XadesBesSigningProfile(signProvider);
        final BasicSignatureOptions opts = new BasicSignatureOptions();
        opts.checkKeyUsage(false)
                .checkCertificateValidity(false);
        signProfile.withBasicSignatureOptions(opts);
        XadesSigner signer = signProfile.newSigner();

        final DataObjectDesc ref = new DataObjectReference("").withTransform(new EnvelopedSignatureTransform())
                .withTransform(new ExclusiveCanonicalXMLWithoutComments());
        SignedDataObjects dataObjs = new SignedDataObjects(ref);

        signer.sign(dataObjs, elemToSign);

        outputDocument(doc, outputName);

        XadesVerificationProfile p = new XadesVerificationProfile(verifyProvider);
        Element sig = (Element) doc.getDocumentElement()
                .getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATURE).item(0);
        SignatureSpecificVerificationOptions verifyOpts = new SignatureSpecificVerificationOptions()
                .checkKeyUsage(verifySignatureKeyUsage);
        XAdESVerificationResult res = p.newVerifier().verify(sig, verifyOpts);
        assertEquals(XAdESForm.BES, res.getSignatureForm());
    }

    /**
     * Create validation provider with a single trusted root CA for tests.
     *
     * @param root    the trusted root CA
     * @param certdir load additional CAs from this directory
     * @return validation provider with the given content
     * @throws Exception
     */
    private CertificateValidationProvider genValidationProvider(final String root, final String certdir)
            throws Exception
    {
        String path = toPlatformSpecificCertDirFilePath(root);
        KeyStore ks = KeyStore.getInstance("JKS");
        // initialize an empty keystore
        ks.load(null, "password".toCharArray());
        try (FileInputStream fis = new FileInputStream(path))
        {
            Certificate anchor = CertificateFactory.getInstance("X.509").generateCertificate(fis);
            ks.setCertificateEntry("testCA", anchor);
        }
        FileSystemDirectoryCertStore certStore = new FileSystemDirectoryCertStore(
                toPlatformSpecificCertDirFilePath(certdir));
        return PKIXCertificateValidationProvider
                .builder(ks)
                .checkRevocation(false)
                .intermediateCertStores(certStore.getStore())
                .build();
    }

    @Test
    void testUncheckedSignBes() throws Exception
    {
        CertificateValidationProvider prov = genValidationProvider("my/TestCA.cer", "my");
        trySignAndVerify(keyingProviderMy, prov, "document.unchecked.signed.bes.xml");
    }

    @Test
    void testUncheckedSignBesGood() throws Exception
    {
        trySignAndVerify(keyingProviderGood, validationProvider, "document.unchecked.signed.bes.good.xml");
    }

    @Test
    void testUncheckedSignBesNoSignKeyUsage() throws Exception
    {
        assertThrows(SigningCertificateKeyUsageException.class, () -> {
            trySignAndVerify(keyingProviderNoSign, validationProvider, "document.unchecked.signed.bes.nosign.xml");
        });
    }

    @Test
    void testUncheckedSignBesNoSignKeyUsageUncheckedVerify() throws Exception
    {
        // same certificate as in testUncheckedSignBesNoSignKeyUsage(), but keyUsage
        // check disabled during verification
        trySignAndVerify(keyingProviderNoSign, validationProvider, "document.unchecked.signed.bes.nosign.xml", false);
    }

    @Test
    void testUncheckedSignBesExpired() throws Exception
    {
        assertThrows(CannotBuildCertificationPathException.class, () -> {
            trySignAndVerify(keyingProviderExp, validationProvider, "document.unchecked.signed.bes.expired.xml");
        });
    }

    @Test
    void testUncheckedSignBesNyv() throws Exception
    {
        assertThrows(CannotBuildCertificationPathException.class, () -> {
            trySignAndVerify(keyingProviderNyv, validationProvider, "document.unchecked.signed.bes.nyv.xml");
        });
    }
}
