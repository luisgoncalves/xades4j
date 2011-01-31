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

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Luís
 */
public class DataObjectDescTest
{
    public DataObjectDescTest()
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

    /**
     * Test of withTransform method, of class DataObjectDesc.
     */
//    @Test
//    public void testWithTransform()
//    {
//        System.out.println("withTransform");
//        DataObjectTransform transf = null;
//        DataObjectDesc instance = new DataObjectInfoImpl();
//        DataObjectDesc expResult = null;
//        DataObjectDesc result = instance.withTransform(transf);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
    /**
     * Test of getTransforms method, of class DataObjectDesc.
     */
//    @Test
//    public void testGetTransforms()
//    {
//        System.out.println("getTransforms");
//        DataObjectDesc instance = new DataObjectInfoImpl();
//        Collection expResult = null;
//        Collection result = instance.getTransforms();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
    /**
     * Test of withDataObjectFormat method, of class DataObjectDesc.
     */
    @Test(expected = IllegalStateException.class)
    public void testWithDataObjectFormatRepeatedInstance()
    {
        System.out.println("withDataObjectFormatRepeatedInstance");

        DataObjectFormatProperty format = new DataObjectFormatProperty();
        DataObjectDesc instance = new DataObjectInfoImpl();

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
        DataObjectDesc instance = new DataObjectInfoImpl();
        DataObjectDesc other = new DataObjectInfoImpl();

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

        DataObjectDesc instance = new DataObjectInfoImpl();
        instance.withCommitmentType(commitment1);
        instance.withCommitmentType(commitment2);
    }

    /**
     * Test of withDataObjectTimeStamp method, of class DataObjectDesc.
     */
//    @Test
//    public void testWithDataObjectTimeStamp()
//    {
//        System.out.println("withDataObjectTimeStamp");
//        DataObjectDesc instance = new DataObjectInfoImpl();
//        DataObjectDesc expResult = null;
//        DataObjectDesc result = instance.withDataObjectTimeStamp();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
    /**
     * Test of withOtherDataObjectProperty method, of class DataObjectDesc.
     */
//    @Test
//    public void testWithOtherDataObjectProperty_OtherSignedDataObjectProperty()
//    {
//        System.out.println("withOtherDataObjectProperty");
//        OtherSignedDataObjectProperty otherSignedDataObjProp = null;
//        DataObjectDesc instance = new DataObjectInfoImpl();
//        DataObjectDesc expResult = null;
//        DataObjectDesc result = instance.withOtherDataObjectProperty(otherSignedDataObjProp);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }

    /**
     * Test of withOtherDataObjectProperty method, of class DataObjectDesc.
     */
//    @Test
//    public void testWithOtherDataObjectProperty_OtherUnsignedDataObjectProperty()
//    {
//        System.out.println("withOtherDataObjectProperty");
//        OtherUnsignedDataObjectProperty otherUnsignedDataObjProp = null;
//        DataObjectDesc instance = new DataObjectInfoImpl();
//        DataObjectDesc expResult = null;
//        DataObjectDesc result = instance.withOtherDataObjectProperty(otherUnsignedDataObjProp);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }

    /**
     * Test of hasProperties method, of class DataObjectDesc.
     */
    @Test
    public void testHasProperties()
    {
        System.out.println("hasProperties");

        DataObjectDesc instance = new DataObjectInfoImpl();
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

        DataObjectDesc instance = new DataObjectInfoImpl();
        assertEquals(instance.getSignedDataObjProps().size(), 0);

        instance.withDataObjectFormat(new DataObjectFormatProperty());
        assertEquals(instance.getSignedDataObjProps().size(), 1);
    }

    /**
     * Test of getUnsignedDataObjProps method, of class DataObjectDesc.
     */
//    @Test
//    public void testGetUnsignedDataObjProps()
//    {
//        System.out.println("getUnsignedDataObjProps");
//        DataObjectDesc instance = new DataObjectInfoImpl();
//        Collection expResult = null;
//        Collection result = instance.getUnsignedDataObjProps();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }

    public class DataObjectInfoImpl extends DataObjectDesc
    {
    }
}
