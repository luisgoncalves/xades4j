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

import xades4j.properties.UnsignedProperties;
import java.util.ArrayList;
import java.util.Collection;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.properties.ArchiveTimeStampProperty;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.properties.UnsignedSignatureProperty;

/**
 *
 * @author Luís
 */
public class XadesSignatureFormatExtenderImplTest extends SignerTestBase
{
    public XadesSignatureFormatExtenderImplTest() throws Exception
    {
    }

    @BeforeClass
    public static void setUpClass() throws Exception
    {
    }

    @AfterClass
    public static void tearDownClass() throws Exception
    {
    }

    @Before
    public void setUp()
    {
    }

    @After
    public void tearDown()
    {
    }

    @Test
    public void testEnrichSignatureWithT() throws Exception
    {
        System.out.println("enrichSignatureWithT");

        Document doc = getDocument("document.signed.bes.xml");
        Element signatureNode = (Element)doc.getElementsByTagNameNS(Constants.SignatureSpecNS, "Signature").item(0);

        XadesSignatureFormatExtenderImpl instance = (XadesSignatureFormatExtenderImpl)new XadesFormatExtenderProfile().getFormatExtender();
        XMLSignature sig = new XMLSignature(signatureNode, "");
        Collection<UnsignedSignatureProperty> usp = new ArrayList<UnsignedSignatureProperty>(1);
        usp.add(new SignatureTimeStampProperty());

        instance.enrichSignature(sig, new UnsignedProperties(usp));

        outputDocument(doc, "document.signed.bes.enriched.t.xml");
    }

    @Test
    public void testEnrichSignatureWithA() throws Exception
    {
        System.out.println("enrichSignatureWithA");

        Document doc = getDocument("document.verified.c.xl.xml");
        Element signatureNode = (Element)doc.getElementsByTagNameNS(Constants.SignatureSpecNS, "Signature").item(0);

        XadesSignatureFormatExtenderImpl instance = (XadesSignatureFormatExtenderImpl)new XadesFormatExtenderProfile().getFormatExtender();
        XMLSignature sig = new XMLSignature(signatureNode, "");
        Collection<UnsignedSignatureProperty> usp = new ArrayList<UnsignedSignatureProperty>(1);
        usp.add(new ArchiveTimeStampProperty());

        instance.enrichSignature(sig, new UnsignedProperties(usp));

        outputDocument(doc, "document.verified.c.xl.a.xml");
    }
}
