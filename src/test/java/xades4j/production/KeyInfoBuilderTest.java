/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2011 Luis Goncalves.
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

import org.apache.xml.security.keys.content.KeyValue;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import xades4j.providers.impl.DefaultX500NameStyleProvider;
import xades4j.utils.SignatureServicesTestBase;

import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Luís
 */
public class KeyInfoBuilderTest extends SignatureServicesTestBase
{
    private static X509Certificate testCertificate;
    private static X509Certificate intermCertificate;
    private static List<X509Certificate> certificates;
    private static ElementIdGenerator idGenerator;

    @BeforeAll
    public static void setUpClass() throws Exception
    {
        org.apache.xml.security.Init.init();

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        testCertificate = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream(toPlatformSpecificCertDirFilePath("my/LG.cer")));
        intermCertificate = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream(toPlatformSpecificCertDirFilePath("my/Interm.cer")));
        certificates = Arrays.asList(testCertificate, intermCertificate);
        idGenerator = ElementIdGenerator.uuid();
    }

    @Test
    void testIncludeCertAndKey() throws Exception
    {
        KeyInfoBuilder keyInfoBuilder = createKeyInfoBuilder(new BasicSignatureOptions()
                .includeSigningCertificate(SigningCertificateMode.SIGNING_CERTIFICATE)
                .includePublicKey(true));
        XMLSignature xmlSignature = getTestSignature();

        keyInfoBuilder.buildKeyInfo(certificates, xmlSignature, idGenerator);

        assertEquals(0, xmlSignature.getSignedInfo().getLength());

        KeyValue kv = xmlSignature.getKeyInfo().itemKeyValue(0);
        assertTrue(kv.getPublicKey().getAlgorithm().startsWith("RSA"));

        assertEquals(1, xmlSignature.getKeyInfo().lengthX509Data());
        assertEquals(1, xmlSignature.getKeyInfo().itemX509Data(0).lengthCertificate());

        XMLX509Certificate x509Certificate = xmlSignature.getKeyInfo().itemX509Data(0).itemCertificate(0);
        assertEquals(testCertificate, x509Certificate.getX509Certificate());
    }

    @Test
    void testIncludeCertChain() throws Exception
    {
        KeyInfoBuilder keyInfoBuilder = createKeyInfoBuilder(new BasicSignatureOptions()
                .includeSigningCertificate(SigningCertificateMode.FULL_CHAIN));
        XMLSignature xmlSignature = getTestSignature();

        keyInfoBuilder.buildKeyInfo(certificates, xmlSignature, idGenerator);

        assertEquals(0, xmlSignature.getSignedInfo().getLength());

        assertEquals(1, xmlSignature.getKeyInfo().lengthX509Data());
        assertEquals(2, xmlSignature.getKeyInfo().itemX509Data(0).lengthCertificate());

        XMLX509Certificate x509Certificate = xmlSignature.getKeyInfo().itemX509Data(0).itemCertificate(0);
        assertEquals(testCertificate, x509Certificate.getX509Certificate());

        x509Certificate = xmlSignature.getKeyInfo().itemX509Data(0).itemCertificate(1);
        assertEquals(intermCertificate, x509Certificate.getX509Certificate());
    }

    @Test
    void testIncludeIssuerSerial() throws Exception
    {
        KeyInfoBuilder keyInfoBuilder = createKeyInfoBuilder(new BasicSignatureOptions()
                .includeIssuerSerial(true));
        XMLSignature xmlSignature = getTestSignature();

        keyInfoBuilder.buildKeyInfo(certificates, xmlSignature, idGenerator);

        assertEquals(1, xmlSignature.getKeyInfo().lengthX509Data());
        assertEquals(1, xmlSignature.getKeyInfo().itemX509Data(0).lengthIssuerSerial());
    }

    @Test
    void testIncludeSubjectName() throws Exception
    {
        KeyInfoBuilder keyInfoBuilder = createKeyInfoBuilder(new BasicSignatureOptions()
                .includeSubjectName(true));
        XMLSignature xmlSignature = getTestSignature();

        keyInfoBuilder.buildKeyInfo(certificates, xmlSignature, idGenerator);

        assertEquals(1, xmlSignature.getKeyInfo().lengthX509Data());
        assertEquals(1, xmlSignature.getKeyInfo().itemX509Data(0).lengthSubjectName());
    }

    @Test
    void testSignKeyInfo() throws Exception
    {
        KeyInfoBuilder keyInfoBuilder = createKeyInfoBuilder(new BasicSignatureOptions()
                .signKeyInfo(true));
        XMLSignature xmlSignature = getTestSignature();

        keyInfoBuilder.buildKeyInfo(certificates, xmlSignature, idGenerator);

        SignedInfo signedInfo = xmlSignature.getSignedInfo();
        assertEquals(1, signedInfo.getLength());

        Node refNode = signedInfo.item(0).getContentsBeforeTransformation().getSubNode();
        assertSame(xmlSignature.getKeyInfo().getElement(), refNode);
    }

    private static KeyInfoBuilder createKeyInfoBuilder(BasicSignatureOptions bso)
    {
        return new KeyInfoBuilder(
                bso,
                new SignatureAlgorithms(),
                new TestAlgorithmsParametersMarshallingProvider(),
                new DefaultX500NameStyleProvider());
    }

    private XMLSignature getTestSignature() throws Exception
    {
        Document doc = getNewDocument();
        XMLSignature xmlSignature = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        xmlSignature.setId("sigId");
        doc.appendChild(xmlSignature.getElement());
        return xmlSignature;
    }
}
