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

import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.algorithms.ExclusiveCanonicalXMLWithoutComments;
import xades4j.properties.DataObjectDesc;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.utils.FileSystemDirectoryCertStore;
import xades4j.verification.SignatureSpecificVerificationOptions;
import xades4j.verification.XAdESForm;
import xades4j.verification.XAdESVerificationResult;
import xades4j.verification.XadesVerificationProfile;

import static org.junit.Assert.assertEquals;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;

import org.apache.xml.security.utils.Constants;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * This class test signing with the keyUsage check disabled.
 * @author Fiona Klute
 */
public class UncheckedSignerBESTest extends SignerTestBase
{
    private KeyingDataProvider keyingProviderGood;
    private KeyingDataProvider keyingProviderNoSign;

    public UncheckedSignerBESTest() throws KeyStoreException
    {
        keyingProviderGood = createFileSystemKeyingDataProvider("PKCS12", "unchecked/good.p12", "password", true);
        keyingProviderNoSign = createFileSystemKeyingDataProvider("PKCS12", "unchecked/noSignKeyUsage.p12", "password",
                true);
    }

    private void trySignAndVerify(final KeyingDataProvider signProvider,
            final CertificateValidationProvider verifyProvider, final String outputName) throws Exception
    {
        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();

        final XadesBesSigningProfile signProfile = new XadesBesSigningProfile(signProvider);
        final BasicSignatureOptions opts = new BasicSignatureOptions();
        opts.checkKeyUsage(false);
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
        XAdESVerificationResult res = p.newVerifier().verify(sig, new SignatureSpecificVerificationOptions());
        assertEquals(res.getSignatureForm(), XAdESForm.BES);
    }

    private CertificateValidationProvider genValidationProvider(final String store, final String pwd,
            final String certdir) throws Exception
    {
        String path = toPlatformSpecificCertDirFilePath(store);
        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(path))
        {
            ks.load(fis, pwd.toCharArray());
        }
        FileSystemDirectoryCertStore certStore = new FileSystemDirectoryCertStore(
                toPlatformSpecificCertDirFilePath(certdir));
        return new PKIXCertificateValidationProvider(ks, false, certStore.getStore());
    }

    @Test
    public void testUncheckedSignBes() throws Exception
    {
        System.out.println("uncheckedSignBes");
        CertificateValidationProvider prov = genValidationProvider("my/myStore", "mystorepass", "my");
        trySignAndVerify(keyingProviderMy, prov, "document.unchecked.signed.bes.xml");
    }

    @Test
    public void testUncheckedSignBesGood() throws Exception
    {
        System.out.println("uncheckedSignBesGood");
        CertificateValidationProvider prov = genValidationProvider("unchecked/trust.jks", "password", "unchecked");
        trySignAndVerify(keyingProviderGood, prov, "document.unchecked.signed.bes.good.xml");
    }

    @Test
    public void testUncheckedSignBesNoSignKeyUsage() throws Exception
    {
        System.out.println("uncheckedSignBesNoSignKeyUsage");
        CertificateValidationProvider prov = genValidationProvider("unchecked/trust.jks", "password", "unchecked");
        // BUG: Validation passes even though the keyUsage is invalid!
        trySignAndVerify(keyingProviderNoSign, prov, "document.unchecked.signed.bes.nosign.xml");
    }
}
