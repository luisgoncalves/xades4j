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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import xades4j.providers.CannotSelectCertificateException;
import xades4j.providers.impl.PKIXCertificateValidationProvider;

import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author Luís
 */
class XadesVerifierErrorsTest extends VerifierTestBase
{
    XadesVerificationProfile mySigsVerificationProfile;
    XadesVerificationProfile nistVerificationProfile;

    @BeforeEach
    public void initialize()
    {
        mySigsVerificationProfile = new XadesVerificationProfile(VerifierTestBase.validationProviderMySigs);
        nistVerificationProfile = new XadesVerificationProfile(VerifierTestBase.validationProviderNist);
    }

    @Test
    void testErrVerifySignedPropsIncorp() throws Exception
    {
        assertThrows(QualifyingPropertiesIncorporationException.class, () -> {
            verifyBadSignature("document.signed.t.bes.badsignedprops.xml", mySigsVerificationProfile);
        });
    }

    @Test
    void testErrVerifySignedPropsIncorpNoRefType() throws Exception
    {
        assertThrows(QualifyingPropertiesIncorporationException.class, () -> {
            verifyBadSignature("document.signed.bes.signedpropsrefnotype.xml",
                    new XadesVerificationProfile(validationProviderPtCc));
        });
    }

    @Test
    void testErrVerifyIncorrectC() throws Exception
    {
        assertThrows(InvalidXAdESFormException.class, () -> {
            verifyBadSignature("document.signed.c.bad.xml", nistVerificationProfile);
        });
    }

    @Test
    void testErrVerifyNoSignCert() throws Exception
    {
        KeyStore ks = createAndLoadJKSKeyStore("be/beStore", "bestorepass");
        PKIXCertificateValidationProvider cvp = PKIXCertificateValidationProvider.builder(ks).checkRevocation(false).build();
        assertThrows(CannotSelectCertificateException.class, () -> {
            verifyBadSignature("TSL_BE.nocert.xml", new XadesVerificationProfile(cvp));
        });
    }

    @Test
    void testErrVerifyChangedDataObj() throws Exception
    {
        assertThrows(ReferenceValueException.class, () -> {
            verifyBadSignature("document.signed.bes.invaliddataobj.xml", mySigsVerificationProfile);
        });
    }

    @Test
    void testErrVerifyChangedSigValue() throws Exception
    {
        assertThrows(SignatureValueException.class, () -> {
            verifyBadSignature("document.signed.bes.invalidsigvalue.xml", mySigsVerificationProfile);
        });
    }

    @Test
    void testErrVerifyCMissingCertRef() throws Exception
    {
        assertThrows(CompleteCertRefsCertNotFoundException.class, () -> {
            verifyBadSignature("document.signed.c.missingcertref.xml", nistVerificationProfile);
        });
    }

    @Test
    void testErrVerifyUnmatchSigTSDigest() throws Exception
    {
        //        DefaultTimeStampTokenProvider tsProv = new DefaultTimeStampTokenProvider(new DefaultMessageDigestProvider());
        //        byte[] tkn = tsProv.getTimeStampToken("badTimeStamp".getBytes(), Constants.ALGO_ID_DIGEST_SHA1).encodedTimeStampToken;
        //
        //        Document doc = getDocument("document.signed.t.bes.xml");
        //        Element encTS = (Element)doc.getElementsByTagNameNS(QualifyingProperty.XADES_XMLNS, "EncapsulatedTimeStamp").item(0);
        //        encTS.setTextContent(Base64.encodeBytes(tkn));
        //        outputDocument(doc, "bad/document.signed.t.bes.badtsdigest.xml");

        assertThrows(TimeStampDigestMismatchException.class, () -> {
            verifyBadSignature("document.signed.t.bes.badtsdigest.xml", mySigsVerificationProfile);
        });
    }

    @Test
    void testErrVerifyCounterSigWithUnallowedTransforms() throws Exception
    {
        assertThrows(CounterSignatureSigValueRefException.class, () -> {
            verifyBadSignature("document.signed.bes.cs.invalidtransforms.xml", mySigsVerificationProfile);
        });
    }

    private static void verifyBadSignature(String sigFileName, XadesVerificationProfile p) throws Exception
    {
        verifySignature("bad/" + sigFileName, p);
    }
}
