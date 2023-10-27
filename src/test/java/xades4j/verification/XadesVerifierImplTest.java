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

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.resolver.implementations.ResolverDirectHTTP;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import xades4j.algorithms.CanonicalXMLWithoutComments;
import xades4j.production.XadesFormatExtenderProfile;
import xades4j.production.XadesSignatureFormatExtender;
import xades4j.properties.CertificateValuesProperty;
import xades4j.properties.CommitmentTypeProperty;
import xades4j.properties.CommitmentTypePropertyBase;
import xades4j.properties.CompleteCertificateRefsProperty;
import xades4j.properties.CounterSignatureProperty;
import xades4j.properties.DataObjectFormatProperty;
import xades4j.properties.IndividualDataObjsTimeStampProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.RevocationValuesProperty;
import xades4j.properties.SigAndRefsTimeStampProperty;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.properties.SigningCertificateProperty;
import xades4j.properties.SigningTimeProperty;
import xades4j.providers.CannotBuildCertificationPathException;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.GregorianCalendar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Luís
 */
public class XadesVerifierImplTest extends VerifierTestBase
{
    XadesVerificationProfile verificationProfile;
    XadesVerificationProfile nistVerificationProfile;

    @BeforeEach
    public void initialize()
    {
        verificationProfile = new XadesVerificationProfile(VerifierTestBase.validationProviderMySigs);
        nistVerificationProfile = new XadesVerificationProfile(VerifierTestBase.validationProviderNist);
    }

    @Test
    public void testVerifyBES() throws Exception
    {
        var result = verifySignature("document.signed.bes.xml");
        assertEquals(XAdESForm.BES, result.getSignatureForm());

        assertEquals(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, result.getSignatureAlgorithmUri());
        assertEquals(new CanonicalXMLWithoutComments().getUri(), result.getCanonicalizationAlgorithmUri());

        assertEquals("CN=Luis Goncalves,OU=CC,O=ISEL,C=PT", result.getValidationCertificate().getSubjectX500Principal().getName());

        var singingTime = result.getPropertiesFilter().getOfType(SigningTimeProperty.class);
        assertEquals(1, singingTime.size());
        var singingCertificate = result.getPropertiesFilter().getOfType(SigningCertificateProperty.class);
        assertEquals(1, singingCertificate.size());

        var signedObjects = result.getSignedDataObjects();
        assertEquals(2, signedObjects.size());

        var signedObjectProperties = signedObjects.stream().findFirst().get().getSignedDataObjProps();
        assertEquals(3, signedObjectProperties.size());

        var dataObjectFormat = signedObjectProperties.stream()
                .filter(it -> it instanceof DataObjectFormatProperty)
                .map(it -> (DataObjectFormatProperty) it)
                .findFirst();
        assertTrue(dataObjectFormat.isPresent());
        assertEquals("text/xml", dataObjectFormat.get().getMimeType());

        var commitmentType = signedObjectProperties.stream()
                .filter(it -> it instanceof CommitmentTypeProperty)
                .map(it -> (CommitmentTypeProperty) it)
                .findFirst();
        assertTrue(commitmentType.isPresent());
        assertEquals(CommitmentTypePropertyBase.PROOF_OF_CREATION_URI, commitmentType.get().getUri());

        var dataObjectTimeStamp = signedObjectProperties.stream()
                .filter(it -> it instanceof IndividualDataObjsTimeStampProperty)
                .map(it -> (IndividualDataObjsTimeStampProperty) it)
                .findFirst();
        assertTrue(dataObjectTimeStamp.isPresent());
    }

    @Test
    public void testVerifyBESWithoutKeyInfo() throws Exception
    {
        var result = verifySignature("document.signed.bes.no-ki.xml");
        assertEquals(XAdESForm.BES, result.getSignatureForm());
    }

    /**
     * Try to verify a test xades BES (no timestamp) in year 2041, expect we
     * can't build the certificate path because certificates are expired.
     */
    @Test
    public void testVerifyBESWithVerificationDate() throws Exception
    {
        String sigFilename = "document.signed.bes.xml";
        Element signatureNode = getSigElement(getDocument(sigFilename));
        XadesVerificationProfile p = new XadesVerificationProfile(VerifierTestBase.validationProviderMySigs);
        XadesVerifier verifier = p.newVerifier();

        assertThrows(CannotBuildCertificationPathException.class, () -> {
            Date verificationDate = new SimpleDateFormat("YYYY").parse("2041");
            verifier.verify(signatureNode,
                    new SignatureSpecificVerificationOptions().setDefaultVerificationDate(verificationDate));
        });
    }

    @Test
    public void testVerifyWithCustomRawVerifier() throws Exception
    {
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

        assertThrows(InvalidSignatureException.class, () -> {
            verifySignature("document.signed.bes.xml", verificationProfile);
        });
    }

    @Test
    public void testVerifyBESPTCC() throws Exception
    {
        var result = verifySignature(
                "document.signed.bes.ptcc.xml",
                new XadesVerificationProfile(validationProviderPtCc),
                new SignatureSpecificVerificationOptions().setDefaultVerificationDate(new GregorianCalendar(2014, 0, 1).getTime()));

        assertEquals(XAdESForm.BES, result.getSignatureForm());
    }

    @Test
    public void testVerifyDetachedBES() throws Exception
    {
        var result = verifySignature(
                "detached.bes.xml",
                new SignatureSpecificVerificationOptions()
                        .useBaseUri(new File("src/test/xml/").toURI().toString())
                        .useResourceResolver(new ResolverLocalFilesystem()));

        assertEquals(XAdESForm.BES, result.getSignatureForm());

        var uri = result.getSignedDataObjects().stream()
                .map(it -> it.getReference().getURI())
                .findFirst();

        assertEquals("document.xml", uri.get());
    }

    @Test
    public void testVerifyBESCounterSig() throws Exception
    {
        var result = verifySignature("document.signed.bes.cs.xml");

        assertEquals(XAdESForm.BES, result.getSignatureForm());

        var counterSignatures = result.getPropertiesFilter().getOfType(CounterSignatureProperty.class);
        assertEquals(1, counterSignatures.size());

        var counterSignature = counterSignatures.stream().findFirst().get();
        assertEquals(XAdESForm.BES, counterSignature.getVerificationResult().getSignatureForm());
    }

    @Test
    public void testVerifyBESCounterSigCounterSig() throws Exception
    {
        var result = verifySignature("document.signed.bes.cs.cs.xml");
        assertEquals(XAdESForm.BES, result.getSignatureForm());
    }

    @Test
    public void testVerifyBESEnrichT() throws Exception
    {
        Document doc = getDocument("document.signed.bes.xml");
        Element signatureNode = getSigElement(doc);

        XadesSignatureFormatExtender formExt = new XadesFormatExtenderProfile().with(DEFAULT_TEST_TSA).getFormatExtender();
        XAdESVerificationResult res = verificationProfile.newVerifier().verify(signatureNode, null, formExt, XAdESForm.T);
        assertEquals(XAdESForm.BES, res.getSignatureForm());

        res = verificationProfile.newVerifier().verify(signatureNode, null);
        assertEquals(XAdESForm.T, res.getSignatureForm());

        outputDocument(doc, "document.verified.bes.t.xml");
    }

    @Test
    public void testVerifyBESExtrnlResEnrichC() throws Exception
    {
        Document doc = getDocument("document.signed.bes.extres.xml");
        Element signatureNode = getSigElement(doc);
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions()
                .useBaseUri("http://luisgoncalves.github.io/xades4j/images/")
                .useResourceResolver(new ResolverDirectHTTP());

        XadesSignatureFormatExtender formExt = new XadesFormatExtenderProfile().with(DEFAULT_TEST_TSA).getFormatExtender();

        XAdESVerificationResult res = nistVerificationProfile.newVerifier().verify(signatureNode, options, formExt, XAdESForm.C);
        assertEquals(XAdESForm.BES, res.getSignatureForm());

        res = nistVerificationProfile.newVerifier().verify(signatureNode, options);
        assertEquals(XAdESForm.C, res.getSignatureForm());

        outputDocument(doc, "document.verified.bes.extres.c.xml");
    }

    @Test
    public void testVerifyTBES() throws Exception
    {
        var result = verifySignature("document.signed.t.bes.xml");

        assertEquals(XAdESForm.T, result.getSignatureForm());

        var signatureTimeStamps = result.getPropertiesFilter().getOfType(SignatureTimeStampProperty.class);
        assertEquals(1, signatureTimeStamps.size());
    }

    @Test
    public void testVerifyEPES1() throws Exception
    {
        verificationProfile.withPolicyDocumentProvider(VerifierTestBase.policyDocumentFinder);
        var result = verifySignature("document.signed.epes_1.xml", verificationProfile);

        assertEquals(XAdESForm.EPES, result.getSignatureForm());
    }

    @Test
    public void testVerifyEPES2() throws Exception
    {
        verificationProfile.withPolicyDocumentProvider(VerifierTestBase.policyDocumentFinder);
        var result = verifySignature("document.signed.epes_2.xml", verificationProfile);
        assertEquals(XAdESForm.EPES, result.getSignatureForm());
    }

    @Test
    public void testVerifyTEPES() throws Exception
    {
        var result = verifySignature("document.signed.t.epes.xml");

        assertEquals(XAdESForm.T, result.getSignatureForm());

        var signatureTimeStamps = result.getPropertiesFilter().getOfType(SignatureTimeStampProperty.class);
        assertEquals(1, signatureTimeStamps.size());
    }

    @Test
    public void testVerifyC() throws Exception
    {
        var result = verifySignature(
                "document.signed.c.xml",
                nistVerificationProfile);

        assertEquals(XAdESForm.C, result.getSignatureForm());

        var signatureTimeStamps = result.getPropertiesFilter().getOfType(SignatureTimeStampProperty.class);
        assertEquals(1, signatureTimeStamps.size());

        var certificateRefs = result.getPropertiesFilter().getOfType(CompleteCertificateRefsProperty.class);
        assertEquals(1, certificateRefs.size());
        var firstCertificateRefs = certificateRefs.iterator().next();
        assertEquals(3, firstCertificateRefs.getCertificates().size());

        var revocationRefs = result.getPropertiesFilter().getOfType(CompleteCertificateRefsProperty.class);
        assertEquals(1, revocationRefs.size());
    }

    @Test
    public void testVerifyDetachedC() throws Exception
    {
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
        Document doc = getDocument("document.signed.c.xml");
        Element signatureNode = getSigElement(doc);

        XadesSignatureFormatExtender formExt = new XadesFormatExtenderProfile().with(DEFAULT_TEST_TSA).getFormatExtender();
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
