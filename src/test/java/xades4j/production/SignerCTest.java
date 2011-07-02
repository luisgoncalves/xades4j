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
package xades4j.production;

import java.io.FileInputStream;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.providers.impl.ValidationDataFromCertValidationProvider;
import xades4j.providers.ValidationDataProvider;
import xades4j.verification.VerifierTestBase;

/**
 *
 * @author Luís
 */
public class SignerCTest extends SignerTestBase
{
    @Test
    public void testSignC() throws Exception
    {
        System.out.println("signC");

        Document doc = getTestDocument();
        Element elemToSign = doc.getDocumentElement();

        ValidationDataProvider vdp = new ValidationDataFromCertValidationProvider(VerifierTestBase.validationProviderNist);
        SignerC signer = (SignerC)new XadesCSigningProfile(keyingProviderNist, vdp).newSigner();
        new Enveloped(signer).sign(elemToSign);

        outputDocument(doc, "document.signed.c.xml");
    }

    @Test
    public void testSignFileDetachedC() throws Exception
    {
        System.out.println("signFileDetachedC");

        ValidationDataProvider vdp = new ValidationDataFromCertValidationProvider(VerifierTestBase.validationProviderNist);
        SignerC signer = (SignerC)new XadesCSigningProfile(keyingProviderNist, vdp).newSigner();

        AnonymousDataObjectReference ref = new AnonymousDataObjectReference(new FileInputStream("license.txt"));
        SignedDataObjects objs = new SignedDataObjects(ref);
        Document doc = getNewDocument();
        signer.sign(objs, doc);

        outputDocument(doc, "detached.c.xml");
    }
}
