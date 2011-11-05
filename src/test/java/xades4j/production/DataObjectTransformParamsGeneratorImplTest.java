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

import org.w3c.dom.NodeList;
import xades4j.utils.SignatureServicesTestBase;
import org.w3c.dom.Document;
import xades4j.production.XPath2FilterTransform.XPathFilter;
import com.google.inject.Injector;
import com.google.inject.Guice;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class DataObjectTransformParamsGeneratorImplTest
{
    @BeforeClass
    public static void setUpClass() throws Exception
    {
    }

    @AfterClass
    public static void tearDownClass() throws Exception
    {
    }

    @Test
    public void testGetParameters() throws Exception
    {
        Document doc = SignatureServicesTestBase.getNewDocument();
        Injector injector = Guice.createInjector(new DefaultProductionBindingsModule());
        DataObjectTransformParamsGeneratorImpl instance = new DataObjectTransformParamsGeneratorImpl(injector);

        DataObjectTransform[] transforms = new DataObjectTransform[]
        {
            new XPathTransform("xpath"),
            new XPath2FilterTransform(XPathFilter.subtract("xpath")),
            new GenericDataObjectTransform("uri", doc.createElement("param1"), doc.createElement("param2"))
        };

        for (DataObjectTransform t : transforms)
        {
            NodeList params = instance.getParameters(t, doc);
            assertNotNull(params);
        }

        transforms = new DataObjectTransform[]
        {
            new EnvelopedSignatureTransform(),
            new GenericDataObjectTransform("uri")
        };

        for (DataObjectTransform t : transforms)
        {
            NodeList params = instance.getParameters(t, doc);
            assertNull(params);
        }
    }
}
