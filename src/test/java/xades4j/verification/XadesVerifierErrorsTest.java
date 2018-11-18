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

import java.security.KeyStore;
import org.junit.Test;
import org.junit.Before;
import xades4j.providers.CannotSelectCertificateException;
import xades4j.providers.impl.PKIXCertificateValidationProvider;

/**
 *
 * @author Luís
 */
public class XadesVerifierErrorsTest extends VerifierTestBase
{
    XadesVerificationProfile mySigsVerificationProfile;
    XadesVerificationProfile nistVerificationProfile;

    @Before
    public void initialize()
    {
        mySigsVerificationProfile = new XadesVerificationProfile(VerifierTestBase.validationProviderMySigs);
        nistVerificationProfile = new XadesVerificationProfile(VerifierTestBase.validationProviderNist);
    }

    @Test(expected = QualifyingPropertiesIncorporationException.class)
    public void testErrVerifySignedPropsIncorp() throws Exception
    {
        System.out.println("errVerifySignedPropsIncorp");
        verifyBadSignature("document.signed.t.bes.badsignedprops.xml", mySigsVerificationProfile);
    }

    @Test(expected = QualifyingPropertiesIncorporationException.class)
    public void testErrVerifySignedPropsIncorpNoRefType() throws Exception
    {
        System.out.println("errVerifySignedPropsIncorpNoRefType");

        verifyBadSignature("document.signed.bes.signedpropsrefnotype.xml",
                new XadesVerificationProfile(validationProviderPtCc));
    }

    @Test(expected = InvalidXAdESFormException.class)
    public void testErrVerifyIncorrectC() throws Exception
    {
        System.out.println("errVerifyIncorrectC");
        verifyBadSignature("document.signed.c.bad.xml",nistVerificationProfile);
    }

    @Test(expected = CannotSelectCertificateException.class)
    public void testErrVerifyNoSignCert() throws Exception
    {
        System.out.println("ErrVerifyNoSignCert");

        KeyStore ks = createAndLoadJKSKeyStore("be/beStore", "bestorepass");
        PKIXCertificateValidationProvider cvp = new PKIXCertificateValidationProvider(ks, false);
        verifyBadSignature("TSL_BE.nocert.xml", new XadesVerificationProfile(cvp));
    }

    @Test(expected = ReferenceValueException.class)
    public void testErrVerifyChangedDataObj() throws Exception
    {
        System.out.println("errVerifyChangedDataObj");
        verifyBadSignature("document.signed.bes.invaliddataobj.xml", mySigsVerificationProfile);
    }

    @Test(expected = SignatureValueException.class)
    public void testErrVerifyChangedSigValue() throws Exception
    {
        System.out.println("errVerifyChangedSigValue");
        verifyBadSignature("document.signed.bes.invalidsigvalue.xml", mySigsVerificationProfile);
    }

    @Test(expected = CompleteCertRefsCertNotFoundException.class)
    public void testErrVerifyCMissingCertRef() throws Exception
    {
        System.out.println("errVerifyCMissingCertRef");
        verifyBadSignature("document.signed.c.missingcertref.xml", nistVerificationProfile);
    }

    @Test(expected = TimeStampDigestMismatchException.class)
    public void testErrVerifyUnmatchSigTSDigest() throws Exception
    {
//        DefaultTimeStampTokenProvider tsProv = new DefaultTimeStampTokenProvider(new DefaultMessageDigestProvider());
//        byte[] tkn = tsProv.getTimeStampToken("badTimeStamp".getBytes(), Constants.ALGO_ID_DIGEST_SHA1).encodedTimeStampToken;
//
//        Document doc = getDocument("document.signed.t.bes.xml");
//        Element encTS = (Element)doc.getElementsByTagNameNS(QualifyingProperty.XADES_XMLNS, "EncapsulatedTimeStamp").item(0);
//        encTS.setTextContent(Base64.encodeBytes(tkn));
//        outputDocument(doc, "bad/document.signed.t.bes.badtsdigest.xml");

        System.out.println("errVerifyUnmatchSigTSDigest");
        verifyBadSignature("document.signed.t.bes.badtsdigest.xml", mySigsVerificationProfile);
    }
    
    @Test(expected = CounterSignatureSigValueRefException.class)
    public void testErrVerifyCounterSigWithUnallowedTransforms() throws Exception
    {
        System.out.println("errVerifyCounterSigWithUnallowedTransforms");
        verifyBadSignature("document.signed.bes.cs.invalidtransforms.xml", mySigsVerificationProfile);
    }

    private static void verifyBadSignature(String sigFileName, XadesVerificationProfile p) throws Exception
    {
        verifySignature("bad/" + sigFileName, p);
    }
}
