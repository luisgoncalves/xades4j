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
package xades4j.properties;

import xades4j.algorithms.XPath2FilterTransform.XPath2Filter;
import xades4j.algorithms.GenericAlgorithm;
import org.w3c.dom.Document;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import xades4j.algorithms.Algorithm;
import xades4j.algorithms.XPath2FilterTransform;
import xades4j.algorithms.XPathTransform;
import xades4j.utils.SignatureServicesTestBase;
import static org.junit.Assert.*;

/**
 *
 * @author Luís
 */
public class DataObjectDescTest
{
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
    public void testWithTransform() throws Exception
    {
        System.out.println("withTransform");
        
        Document doc = SignatureServicesTestBase.getNewDocument();
        DataObjectDesc instance = new DataObjectDescTestImpl()
            .withTransform(new XPathTransform("xpath"))
            .withTransform(XPath2Filter.subtract("xpath1").intersect("xpath2"))
            .withTransform(new GenericAlgorithm("uri", doc.createElement("param1"),doc.createElement("param2")));

        Algorithm[] transforms = instance.getTransforms().toArray(new Algorithm[0]);

        assertEquals(3, transforms.length);
        assertEquals(XPathTransform.class, transforms[0].getClass());
        assertEquals(XPath2FilterTransform.class, transforms[1].getClass());
        assertEquals(GenericAlgorithm.class, transforms[2].getClass());
    }

    @Test(expected = IllegalStateException.class)
    public void testWithDataObjectFormatRepeatedInstance()
    {
        System.out.println("withDataObjectFormatRepeatedInstance");

        DataObjectFormatProperty format = new DataObjectFormatProperty();
        DataObjectDesc instance = new DataObjectDescTestImpl();

        instance.withDataObjectFormat(format);
        instance.withDataObjectFormat(format);
    }

    /**
     * Test of withDataObjectFormat method, of class DataObjectDesc.
     */
    public void testWithDataObjectFormatMultipleTargets()
    {
        System.out.println("withDataObjectFormatMultipleTargets");

        DataObjectFormatProperty format = new DataObjectFormatProperty();
        DataObjectDesc instance = new DataObjectDescTestImpl();
        DataObjectDesc other = new DataObjectDescTestImpl();

        other.withDataObjectFormat(format);
        instance.withDataObjectFormat(format);
    }

    /**
     * Test of withCommitmentType method, of class DataObjectDesc.
     */
    @Test
    public void testWithCommitmentType()
    {
        System.out.println("withCommitmentType");

        CommitmentTypeProperty commitment1 = CommitmentTypeProperty.proofOfApproval();
        CommitmentTypeProperty commitment2 = CommitmentTypeProperty.proofOfCreation();

        DataObjectDesc instance = new DataObjectDescTestImpl();
        instance.withCommitmentType(commitment1);
        instance.withCommitmentType(commitment2);
    }

    /**
     * Test of hasProperties method, of class DataObjectDesc.
     */
    @Test
    public void testHasProperties()
    {
        System.out.println("hasProperties");

        DataObjectDesc instance = new DataObjectDescTestImpl();
        assertEquals(instance.hasProperties(), false);

        instance.withDataObjectFormat(new DataObjectFormatProperty());
        assertEquals(instance.hasProperties(), true);
    }

    /**
     * Test of getSignedDataObjProps method, of class DataObjectDesc.
     */
    @Test
    public void testGetSignedDataObjProps()
    {
        System.out.println("getSignedDataObjProps");

        DataObjectDesc instance = new DataObjectDescTestImpl();
        assertEquals(instance.getSignedDataObjProps().size(), 0);

        instance.withDataObjectFormat(new DataObjectFormatProperty());
        assertEquals(instance.getSignedDataObjProps().size(), 1);
    }

    public class DataObjectDescTestImpl extends DataObjectDesc
    {
    }
}
