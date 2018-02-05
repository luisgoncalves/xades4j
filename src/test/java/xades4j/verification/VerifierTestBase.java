/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
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

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.properties.ObjectIdentifier;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.TSACertificateValidationProvider;
import xades4j.utils.FileSystemDirectoryCertStore;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.providers.impl.PKIXTSACertificateValidationProvider;
import xades4j.providers.SignaturePolicyDocumentProvider;
import xades4j.utils.SignatureServicesTestBase;

/**
 *
 * @author Luís
 */
public class VerifierTestBase extends SignatureServicesTestBase
{
    static SignaturePolicyDocumentProvider policyDocumentFinder;
    public static CertificateValidationProvider validationProviderMySigs;
    public static TSACertificateValidationProvider tsaValidationProviderMySigs;
    public static CertificateValidationProvider validationProviderNist;
    public static TSACertificateValidationProvider tsaValidationProviderNist;
    public static CertificateValidationProvider validationProviderPtCc;

    static
    {
        try
        {
            policyDocumentFinder = new SignaturePolicyDocumentProvider()
            {
                @Override
                public InputStream getSignaturePolicyDocumentStream(
                        ObjectIdentifier sigPolicyId)
                {
                    return new ByteArrayInputStream("Test policy input stream".getBytes());
                }
            };

            // Validation provider with certificates from "my" folder. Used for
            // signatures without revocation data.
            FileSystemDirectoryCertStore certStore = createDirectoryCertStore("my");
            KeyStore ks = createAndLoadJKSKeyStore("my/myStore", "mystorepass");
            validationProviderMySigs = new PKIXCertificateValidationProvider(ks,
                                                    false,
                                                    certStore.getStore());
            tsaValidationProviderMySigs = new PKIXTSACertificateValidationProvider(ks,
                                                    false,
                                                    certStore.getStore());

            // Validation provider with certificates/CRL from "csrc.nist" folder
            // and TSA CRL. Used for signatures with complete validation data.
            certStore = createDirectoryCertStore("csrc.nist");
            FileSystemDirectoryCertStore gvaCRLStore = createDirectoryCertStore("gva");
            ks = createAndLoadJKSKeyStore("csrc.nist/trustAnchor", "password");
            validationProviderNist = new PKIXCertificateValidationProvider(ks,
                                                    true,
                                                    certStore.getStore(),
                                                    gvaCRLStore.getStore());
            tsaValidationProviderNist = new PKIXTSACertificateValidationProvider(ks,
                                                    true,
                                                    certStore.getStore(),
                                                    gvaCRLStore.getStore());

            // Validation provider for "pt" folder. Used for signatures produced
            // with the PT citizen card.
            certStore = createDirectoryCertStore("pt");
            try
            {
                ks = KeyStore.getInstance("Windows-ROOT");
                ks.load(null);
                validationProviderPtCc = new PKIXCertificateValidationProvider(ks, false, certStore.getStore());
            } catch (Exception e)
            {
                // Not on windows platform...
            }
        } catch (Exception ex)
        {
            throw new NullPointerException("VerifierTestBase init failed: " + ex.getMessage());
        }
    }

    protected static XAdESForm verifySignature(String sigFileName) throws Exception
    {
        return verifySignature(sigFileName, new XadesVerificationProfile(VerifierTestBase.validationProviderMySigs,
                VerifierTestBase.tsaValidationProviderMySigs));
    }
    
    protected static XAdESForm verifySignature(
            String sigFileName,
            XadesVerificationProfile p) throws Exception
    {
        return verifySignature(sigFileName, p, null);
    }
    
    protected static XAdESForm verifySignature(
            String sigFileName,
            SignatureSpecificVerificationOptions options) throws Exception
    {
        return verifySignature(sigFileName, new XadesVerificationProfile(VerifierTestBase.validationProviderMySigs,
                VerifierTestBase.tsaValidationProviderMySigs), options);
    }
    
    private static XAdESForm verifySignature(
            String sigFileName,
            XadesVerificationProfile p,
            SignatureSpecificVerificationOptions options) throws Exception
    {
        Element signatureNode = getSigElement(getDocument(sigFileName));
        XAdESVerificationResult res = p.newVerifier().verify(signatureNode, options);
        return res.getSignatureForm();
    }

    static public Element getSigElement(Document doc) throws Exception
    {
        return (Element)doc.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATURE).item(0);
    }

    protected static KeyStore createAndLoadJKSKeyStore(String path, String pwd) throws Exception
    {
        path = toPlatformSpecificFilePath("./src/test/cert/" + path);
        FileInputStream fis = new FileInputStream(path);
        KeyStore ks = KeyStore.getInstance("jks");
        ks.load(fis, pwd.toCharArray());
        fis.close();
        return ks;
    }

    protected static FileSystemDirectoryCertStore createDirectoryCertStore(
            String dir) throws CertificateException, CRLException
    {
        dir = toPlatformSpecificFilePath("./src/test/cert/" + dir);
        return new FileSystemDirectoryCertStore(dir);
    }
}
