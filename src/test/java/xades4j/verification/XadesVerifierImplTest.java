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

import java.io.File;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assume.assumeTrue;

import java.io.FileInputStream;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import xades4j.production.XadesFormatExtenderProfile;
import xades4j.production.XadesSignatureFormatExtender;
import xades4j.properties.CertificateValuesProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.RevocationValuesProperty;
import xades4j.properties.SigAndRefsTimeStampProperty;
import xades4j.providers.CannotBuildCertificationPathException;

/**
 *
 * @author Luís
 */
public class XadesVerifierImplTest extends VerifierTestBase
{
    XadesVerificationProfile verificationProfile;
    XadesVerificationProfile nistVerificationProfile;

    @Before
    public void initialize()
    {
        verificationProfile = new XadesVerificationProfile(VerifierTestBase.validationProviderMySigs);
        nistVerificationProfile = new XadesVerificationProfile(VerifierTestBase.validationProviderNist);
    }

    @Test
    public void testVerifyBES() throws Exception
    {
        System.out.println("verifyBES");
        XAdESForm f = verifySignature("document.signed.bes.xml");
        assertEquals(XAdESForm.BES, f);
    }

    /**
     * Try to verify a test xades BES (no timestamp) in year 2041, expect we
     * can't build the certificate path because certificates are expired.
     */
    @Test(expected = CannotBuildCertificationPathException.class)
    public void testVerifyBESWithVerificationDate() throws Exception
    {
        System.out.println("testVerifyBESWithVerificationDate");
        String sigFilename = "document.signed.bes.xml";
        Element signatureNode = getSigElement(getDocument(sigFilename));
        XadesVerificationProfile p = new XadesVerificationProfile(VerifierTestBase.validationProviderMySigs);
        Date verificationDate = new SimpleDateFormat("YYYY").parse("2041");
        p.newVerifier().verify(signatureNode,
                new SignatureSpecificVerificationOptions().setDefaultVerificationDate(verificationDate));
    }

    @Test(expected = InvalidSignatureException.class)
    public void testVerifyWithCustomRawVerifier() throws Exception
    {
        System.out.println("verifyWithCustomRawVerifier");
        verificationProfile.withRawSignatureVerifier(new RawSignatureVerifier()
        {
            @Override
            public void verify(RawSignatureVerifierContext ctx) throws InvalidSignatureException
            {
                // Do something usefull with the signature
                // ctx.getSignature().getSignedInfo().item(0)...
                throw new InvalidSignatureException("Rejected by RawSignatureVerifier");
            }
        });
        XAdESForm f = verifySignature("document.signed.bes.xml", verificationProfile);
        assertEquals(XAdESForm.BES, f);
    }

    @Test
    public void testVerifyDetachedBES() throws Exception
    {
        System.out.println("verifyDetachedBES");
        XAdESForm f = verifySignature(
                "detached.bes.xml",
                new SignatureSpecificVerificationOptions().useBaseUri(new File("src/test/xml/").toURI().toString()));
        assertEquals(XAdESForm.BES, f);
    }

    @Test
    public void testVerifyBESCounterSig() throws Exception
    {
        System.out.println("verifyBESCounterSig");
        XAdESForm f = verifySignature("document.signed.bes.cs.xml");
        assertEquals(XAdESForm.BES, f);
    }
    
    @Test
    public void testVerifyBESCounterSigCounterSig() throws Exception
    {
        System.out.println("verifyBESCounterSigCounterSig");
        XAdESForm f = verifySignature("document.signed.bes.cs.cs.xml");
        assertEquals(XAdESForm.BES, f);
    }

    @Test
    public void testVerifyBESEnrichT() throws Exception
    {
        System.out.println("verifyBESEnrichT");

        Document doc = getDocument("document.signed.bes.xml");
        Element signatureNode = getSigElement(doc);

        XadesSignatureFormatExtender formExt = new XadesFormatExtenderProfile().getFormatExtender();
        XAdESVerificationResult res = verificationProfile.newVerifier().verify(signatureNode, null, formExt, XAdESForm.T);
        assertEquals(XAdESForm.BES, res.getSignatureForm());

        res = verificationProfile.newVerifier().verify(signatureNode, null);
        assertEquals(XAdESForm.T, res.getSignatureForm());

        outputDocument(doc, "document.verified.bes.t.xml");
    }

    @Test
    public void testVerifyBESExtrnlResEnrichC() throws Exception
    {
        System.out.println("verifyBESExtrnlResEnrichC");

        Document doc = getDocument("document.signed.bes.extres.xml");
        Element signatureNode = getSigElement(doc);
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().useBaseUri("http://www.ietf.org/rfc/");

        XadesSignatureFormatExtender formExt = new XadesFormatExtenderProfile().getFormatExtender();

        XAdESVerificationResult res = nistVerificationProfile.newVerifier().verify(signatureNode, options, formExt, XAdESForm.C);
        assertEquals(XAdESForm.BES, res.getSignatureForm());

        res = nistVerificationProfile.newVerifier().verify(signatureNode, options);
        assertEquals(XAdESForm.C, res.getSignatureForm());

        outputDocument(doc, "document.verified.bes.extres.c.xml");
    }

    @Test
    public void testVerifyTBES() throws Exception
    {
        System.out.println("verifyTBES");
        XAdESForm f = verifySignature("document.signed.t.bes.xml");
        assertEquals(XAdESForm.T, f);
    }

    @Test
    public void testVerifyEPES1() throws Exception
    {
        System.out.println("verifyEPES 1");
        verificationProfile.withPolicyDocumentProvider(VerifierTestBase.policyDocumentFinder);
        XAdESForm f = verifySignature("document.signed.epes_1.xml", verificationProfile);
        assertEquals(XAdESForm.EPES, f);
    }
    
    @Test
    public void testVerifyEPES2() throws Exception
    {
        System.out.println("verifyEPES 2");
        verificationProfile.withPolicyDocumentProvider(VerifierTestBase.policyDocumentFinder);
        XAdESForm f = verifySignature("document.signed.epes_2.xml", verificationProfile);
        assertEquals(XAdESForm.EPES, f);
    }

    @Test
    public void testVerifyTEPES() throws Exception
    {
        System.out.println("verifyTEPES");
        XAdESForm f = verifySignature("document.signed.t.epes.xml");
        assertEquals(XAdESForm.T, f);
    }

    @Test
    public void testVerifyTPTCC() throws Exception
    {
        System.out.println("verifyTPtCC");
        assumeTrue(onWindowsPlatform() && null != validationProviderPtCc);

        XAdESForm f = verifySignature("document.signed.t.bes.ptcc.xml",
                new XadesVerificationProfile(validationProviderPtCc));
        assertEquals(XAdESForm.T, f);
    }

    @Test
    public void testVerifyC() throws Exception
    {
        System.out.println("verifyC");
        XAdESForm f = verifySignature(
                "document.signed.c.xml",
                nistVerificationProfile);
        assertEquals(XAdESForm.C, f);
    }

    @Test
    public void testVerifyDetachedC() throws Exception
    {
        System.out.println("verifyDetachedC");

        Document doc = getDocument("detached.c.xml");
        Element signatureNode = getSigElement(doc);
        XadesVerifier verifier = nistVerificationProfile.newVerifier();

        InputStream is = new FileInputStream("license.txt");
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions().useDataForAnonymousReference(is);
        XAdESVerificationResult res = verifier.verify(signatureNode, options);

        // The caller must close the stream.
        is.close();

        assertEquals(XAdESForm.C, res.getSignatureForm());
    }

    @Test
    public void testVerifyCEnrichXL() throws Exception
    {
        System.out.println("verifyCEnrichXL");

        Document doc = getDocument("document.signed.c.xml");
        Element signatureNode = getSigElement(doc);

        XadesSignatureFormatExtender formExt = new XadesFormatExtenderProfile().getFormatExtender();
        XAdESVerificationResult res = nistVerificationProfile.newVerifier().verify(signatureNode, null, formExt, XAdESForm.X_L);

        assertEquals(XAdESForm.C, res.getSignatureForm());
        assertPropElementPresent(signatureNode, SigAndRefsTimeStampProperty.PROP_NAME);
        assertPropElementPresent(signatureNode, CertificateValuesProperty.PROP_NAME);
        assertPropElementPresent(signatureNode, RevocationValuesProperty.PROP_NAME);

        outputDocument(doc, "document.verified.c.xl.xml");
    }

    private static void assertPropElementPresent(
            Element sigElem,
            String elemName)
    {
        NodeList props = sigElem.getElementsByTagNameNS(QualifyingProperty.XADES_XMLNS, elemName);
        assertFalse(props.getLength() == 0);
    }
}
