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

import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.xml.security.keys.content.KeyValue;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import xades4j.providers.impl.DefaultX500NameStyleProvider;
import xades4j.utils.SignatureServicesTestBase;

/**
 *
 * @author Luís
 */
public class KeyInfoBuilderTest extends SignatureServicesTestBase
{
    private static X509Certificate testCertificate;

    @BeforeClass
    public static void setUpClass() throws Exception
    {
        org.apache.xml.security.Init.init();

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        testCertificate = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream(toPlatformSpecificCertDirFilePath("my/LG.cer")));
    }

    @Test
    public void testIncludeCertAndKey() throws Exception
    {
        System.out.println("includeCertAndKey");

        KeyInfoBuilder keyInfoBuilder = new KeyInfoBuilder(
                new BasicSignatureOptions().includeSigningCertificate(true).includePublicKey(true),
                new TestAlgorithmsProvider(),
                new TestAlgorithmsParametersMarshallingProvider(),
                new DefaultX500NameStyleProvider());
        XMLSignature xmlSignature = getTestSignature();

        keyInfoBuilder.buildKeyInfo(testCertificate, xmlSignature);

        Assert.assertEquals(0, xmlSignature.getSignedInfo().getLength());

        KeyValue kv = xmlSignature.getKeyInfo().itemKeyValue(0);
        Assert.assertTrue(kv.getPublicKey().getAlgorithm().startsWith("RSA"));

        XMLX509Certificate x509Certificate = xmlSignature.getKeyInfo().itemX509Data(0).itemCertificate(0);
        Assert.assertEquals(testCertificate, x509Certificate.getX509Certificate());
    }
    
    @Test
    public void testIncludeIssuerSerial() throws Exception
    {
        System.out.println("includeIssuerSerial");

        KeyInfoBuilder keyInfoBuilder = new KeyInfoBuilder(
                new BasicSignatureOptions().includeIssuerSerial(true),
                new TestAlgorithmsProvider(),
                new TestAlgorithmsParametersMarshallingProvider(),
                new DefaultX500NameStyleProvider());
        XMLSignature xmlSignature = getTestSignature();

        keyInfoBuilder.buildKeyInfo(testCertificate, xmlSignature);

        Assert.assertEquals(1, xmlSignature.getKeyInfo().lengthX509Data());
        Assert.assertEquals(1, xmlSignature.getKeyInfo().itemX509Data(0).lengthIssuerSerial());
    }
    
    @Test
    public void testIncludeSubjectName() throws Exception
    {
        System.out.println("includeSubjectName");

        KeyInfoBuilder keyInfoBuilder = new KeyInfoBuilder(
                new BasicSignatureOptions().includeSubjectName(true),
                new TestAlgorithmsProvider(),
                new TestAlgorithmsParametersMarshallingProvider(),
                new DefaultX500NameStyleProvider());
        XMLSignature xmlSignature = getTestSignature();

        keyInfoBuilder.buildKeyInfo(testCertificate, xmlSignature);

        Assert.assertEquals(1, xmlSignature.getKeyInfo().lengthX509Data());
        Assert.assertEquals(1, xmlSignature.getKeyInfo().itemX509Data(0).lengthSubjectName());
    }

    @Test
    public void testSignKeyInfo() throws Exception
    {
        System.out.println("signKeyInfo");

        KeyInfoBuilder keyInfoBuilder = new KeyInfoBuilder(
                new BasicSignatureOptions().signKeyInfo(true),
                new TestAlgorithmsProvider(),
                new TestAlgorithmsParametersMarshallingProvider(),
                new DefaultX500NameStyleProvider());
        XMLSignature xmlSignature = getTestSignature();

        keyInfoBuilder.buildKeyInfo(testCertificate, xmlSignature);

        SignedInfo signedInfo = xmlSignature.getSignedInfo();
        Assert.assertEquals(1, signedInfo.getLength());

        Node refNode = signedInfo.item(0).getContentsBeforeTransformation().getSubNode();
        Assert.assertSame(xmlSignature.getKeyInfo().getElement(), refNode);
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
