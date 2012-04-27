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
import static org.junit.Assert.*;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.utils.DOMHelper;
import xades4j.utils.FileSystemDirectoryCertStore;

/**
 *
 * @author Luís
 */
public class VerifyExternalSigsTest extends VerifierTestBase
{
    @Test
    public void testVerifyPTTSL() throws Exception
    {
        if (!onWindowsPlatform())
            fail("Test written for Windows-ROOT certificate repository");

        FileSystemDirectoryCertStore certStore = createDirectoryCertStore("tsl/pt");
        KeyStore ks = KeyStore.getInstance("Windows-ROOT");
        ks.load(null);
        PKIXCertificateValidationProvider cvp = new PKIXCertificateValidationProvider(ks, false, certStore.getStore());
        verifyTSL("TSL_PT.xml", cvp);
    }

    @Test
    public void testVerifyBETSL() throws Exception
    {
        KeyStore ks = createAndLoadJKSKeyStore("tsl/be/beStore", "bestorepass");
        PKIXCertificateValidationProvider cvp = new PKIXCertificateValidationProvider(ks, false);
        verifyTSL("TSL_BE.xml", cvp);
    }

    @Test
    public void testVerifyESTSL() throws Exception
    {
        KeyStore ks = createAndLoadJKSKeyStore("tsl/es/esStore", "esstorepass");
        FileSystemDirectoryCertStore certStore = createDirectoryCertStore("tsl/es");
        PKIXCertificateValidationProvider cvp = new PKIXCertificateValidationProvider(ks, false, certStore.getStore());
        verifyTSL("TSL_ES.xml", cvp);
    }
    
    @Test
    public void testVerifyITTSL() throws Exception
    {
        KeyStore ks = createAndLoadJKSKeyStore("tsl/it/itStore", "itstorepass");
        FileSystemDirectoryCertStore certStore = createDirectoryCertStore("tsl/it");
        PKIXCertificateValidationProvider cvp = new PKIXCertificateValidationProvider(ks, false, certStore.getStore());
        verifyTSL("TSL_IT.xml", cvp);
    } 

//    @Test
//    public void testVerifySKTSL() throws Exception
//    {
//        // Couldn't get this one to work. The certificate's issuer name didn't match
//        // the issuer on KeyInfo nor in SigningCertificate. This is very weird because
//        // everything appears to be ok.
//        // Still, I commented the library's code to skip those checks and the
//        // properties on the signature were valid.
//
//        KeyStore ks = createKeyStore("sk/skStore", "skstorepass");
//        PKIXCertificateValidationProvider cvp = new PKIXCertificateValidationProvider(ks, false);
//        SignaturePolicyDocumentProvider spp = new SignaturePolicyDocumentProvider()
//        {
//            @Override
//            public InputStream getSignaturePolicyDocumentStream(
//                    ObjectIdentifier sigPolicyId)
//            {
//                if (!sigPolicyId.getIdentifierType().equals(IdentifierType.OIDAsURI) ||
//                        !sigPolicyId.getIdentifier().equals("1.3.158.36061701.0.0.1.10.4.0.12"))
//                    return null;
//                try
//                {
//                    return new FileInputStream("./src/test/cert/tsl/sk/20100823000000zsignaturepolicy.der");
//                } catch (FileNotFoundException ex)
//                {
//                    return null;
//                }
//            }
//        };
//        verifyTSL("TSL_SK.xml", new XadesVerificationProfile(cvp).withPolicyDocumentProvider(spp));
//    }
    private void verifyTSL(String fileName, CertificateValidationProvider cvp) throws Exception
    {
        verifyTSL(fileName, new XadesVerificationProfile(cvp));
    }

    private void verifyTSL(String fileName, XadesVerificationProfile p) throws Exception
    {
        System.out.println("verify " + fileName);

        XAdESForm f = verifySignature(fileName, p);

        System.out.println("form: " + f.toString());
    }

    @Test
    public void testVerifyPetition() throws Exception
    {
        System.out.println("verifyPetition");

        FileSystemDirectoryCertStore certStore = createDirectoryCertStore("petition");
        KeyStore ks = createAndLoadJKSKeyStore("petition/signitStore", "signitstorepass");
        PKIXCertificateValidationProvider cvp = new PKIXCertificateValidationProvider(ks, false, certStore.getStore());

        Document doc = getDocument("Petition_1285054657304.xml");

        // Set the XML ID of the Petition element.
        Element petitionElem = DOMHelper.getFirstChildElement(doc.getDocumentElement());
        petitionElem.setIdAttribute("id", true);

        XAdESForm f = verifySignature(getSigElement(doc), new XadesVerificationProfile(cvp));
        assertEquals(f, XAdESForm.T);
    }
}
