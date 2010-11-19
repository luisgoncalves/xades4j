/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA
 */
package xades4j.verification;

import java.security.KeyStore;
import org.junit.Test;
import static org.junit.Assert.*;
import xades4j.providers.CannotSelectCertificateException;
import xades4j.providers.impl.PKIXCertificateValidationProvider;

/**
 *
 * @author Luís
 */
public class XadesVerifierErrorsTest extends VerifierTestBase
{
    @Test(expected = QualifyingPropertiesIncorporationException.class)
    public void testErrVerifySignedPropsIncorp() throws Exception
    {
        System.out.println("errVerifySignedPropsIncorp");
        verifySignature("bad/document.signed.t.bes.badsignedprops.xml",
                new XadesVerificationProfile(validationProviderMySigs));
    }

    @Test(expected = QualifyingPropertiesIncorporationException.class)
    public void testErrVerifySignedPropsIncorpNoRefType() throws Exception
    {
        System.out.println("errVerifySignedPropsIncorpNoRefType");

        if (!onWindowsPlatform() || null == validationProviderPtCc)
            fail("Test written for Windows-ROOT certificate repository");

        verifySignature("bad/document.signed.bes.signedpropsrefnotype.xml",
                new XadesVerificationProfile(validationProviderMySigs));
    }

    @Test(expected = InvalidXAdESFormException.class)
    public void testErrVerifyIncorrectC() throws Exception
    {
        System.out.println("errVerifyIncorrectC");
        verifySignature("bad/document.signed.c.bad.xml",
                new XadesVerificationProfile(validationProviderNist));
    }

    @Test(expected = CannotSelectCertificateException.class)
    public void testErrVerifyNoSignCert() throws Exception
    {
        System.out.println("ErrVerifyNoSignCert");

        KeyStore ks = createAndLoadJKSKeyStore("tsl/be/beStore", "bestorepass");
        PKIXCertificateValidationProvider cvp = new PKIXCertificateValidationProvider(ks, false);
        verifySignature("bad/TSL_BE.nocert.xml", new XadesVerificationProfile(cvp));
    }

    @Test(expected = ReferenceValueException.class)
    public void testErrVerifyChangedDataObj() throws Exception
    {
        System.out.println("errVerifyChangedDataObj");
        verifySignature("bad/document.signed.bes.invaliddataobj.xml",
                new XadesVerificationProfile(validationProviderMySigs));
    }

    @Test(expected = SignatureValueException.class)
    public void testErrVerifyChangedSigValue() throws Exception
    {
        System.out.println("errVerifyChangedSigValue");
        verifySignature("bad/document.signed.bes.invalidsigvalue.xml",
                new XadesVerificationProfile(validationProviderMySigs));
    }

    @Test(expected = CompleteCertRefsCertNotFoundException.class)
    public void testErrVerifyCMissingCertRef() throws Exception
    {
        System.out.println("errVerifyCMissingCertRef");
        verifySignature("bad/document.signed.c.missingcertref.xml",
                new XadesVerificationProfile(validationProviderNist));
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
        verifySignature("bad/document.signed.t.bes.badtsdigest.xml",
                new XadesVerificationProfile(validationProviderMySigs));
    }
}
