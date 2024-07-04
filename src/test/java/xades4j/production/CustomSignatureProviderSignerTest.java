/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2024 Luis Goncalves.
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
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.properties.DataObjectDesc;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.verification.SignatureSpecificVerificationOptions;
import xades4j.verification.XAdESForm;
import xades4j.verification.XAdESVerificationResult;
import xades4j.verification.XadesVerificationProfile;
import xades4j.verification.XadesVerifier;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Exemplifies usage of a custom JCA provider that delegates the signature operation to an external system.
 *
 * @see <a href="https://github.com/luisgoncalves/xades4j/issues/287">https://github.com/luisgoncalves/xades4j/issues/287</a> for the reasoning
 */
public class CustomSignatureProviderSignerTest extends SignerTestBase
{
    static final ExternalSignatureSystemProvider signatureProvider = new ExternalSignatureSystemProvider();

    @BeforeAll
    static void addProvider()
    {
        assert Security.addProvider(signatureProvider) != -1;
    }

    @AfterAll
    static void removeProvider()
    {
        Security.removeProvider(signatureProvider.getName());
    }

    @Test
    void run() throws Exception
    {
        Document doc = getTestDocument();
        Element root = doc.getDocumentElement();

        // Sign

        KeyingDataProvider keyingDataProvider = signatureProvider.getKeyingDataProvider();
        XadesSigner signer = new XadesBesSigningProfile(keyingDataProvider).newSigner();

        DataObjectDesc obj1 = new DataObjectReference('#' + root.getAttribute("Id")).withTransform(new EnvelopedSignatureTransform());
        SignedDataObjects dataObjs = new SignedDataObjects(obj1);
        signer.sign(dataObjs, root);

        // Verify

        CertificateValidationProvider certificateValidationProvider = ExternalSignatureSystem.getCertificateValidationProvider();
        XadesVerifier verifier = new XadesVerificationProfile(certificateValidationProvider).newVerifier();

        Element signature = (Element) root.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATURE).item(0);
        XAdESVerificationResult result = verifier.verify(signature, new SignatureSpecificVerificationOptions());
        assertEquals(XAdESForm.BES, result.getSignatureForm());
    }
}
