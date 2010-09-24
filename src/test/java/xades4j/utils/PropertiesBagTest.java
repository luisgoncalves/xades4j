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
package xades4j.utils;

import xades4j.properties.SigningTimeProperty;
import xades4j.properties.DataObjectFormatProperty;
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
public class PropertiesBagTest
{
    public PropertiesBagTest()
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

//    @Test
//    public void jaxbTest() throws Exception
//    {
//
//        DocumentBuilderFactory fac = DocumentBuilderFactory.newInstance();
//        fac.setNamespaceAware(true);
//        Document doc = fac.newDocumentBuilder().parse(new FileInputStream(".\\src\\test\\resources\\dummy.xml"));
//
//        // Create the JAXB unmarshaller.
//        JAXBContext jaxbContext = JAXBContext.newInstance(XmlQualifyingPropertiesType.class);
//        // Create the JAXB unmarshaller and unmarshalProperties the root JAXB element
//        Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
//        ValidationEventCollector col = new ValidationEventCollector();
//        unmarshaller.setEventHandler(col);
//        JAXBElement<XmlQualifyingPropertiesType> qualifPropsElem = (JAXBElement<XmlQualifyingPropertiesType>)unmarshaller.unmarshal(doc.getDocumentElement());
//
//        //int size = qualifPropsElem.getValue().getUnsignedProperties().getUnsignedDataObjectProperties().getUnsignedDataObjectProperty().size();
//
//        Calendar c = qualifPropsElem.getValue().getSignedProperties().getSignedSignatureProperties().getSigningTime();
//
//        XmlCertIDListType certs = qualifPropsElem.getValue().getSignedProperties().getSignedSignatureProperties().getSigningCertificate();
//        Object iss = certs.getCert().get(0).getIssuerSerial();
//        if (null == iss)
//            System.out.println("WAS NULL");
//    }

    /**
     * Test of put method, of class PropertiesSet.
     */
    @Test(expected = IllegalStateException.class)
    public void testPut()
    {
        System.out.println("put");
        SigningTimeProperty prop1 = new SigningTimeProperty(), prop2 = new SigningTimeProperty();
        DataObjectFormatProperty prop3 = new DataObjectFormatProperty();

        PropertiesSet instance = new PropertiesSet(2);
        instance.put(prop1);
        instance.put(prop3);
        instance.put(prop2);
    }

    /**
     * Test of add method, of class PropertiesSet, with {@code null} value.
     */
    @Test(expected = NullPointerException.class)
    public void testAddNull()
    {
        System.out.println("addNull");
        PropertiesSet instance = new PropertiesSet(0);
        instance.add(null);
    }

    /**
     * Test of add method, of class PropertiesSet.
     */
    @Test(expected = IllegalStateException.class)
    public void testAdd()
    {
        System.out.println("add");
        SigningTimeProperty prop1 = new SigningTimeProperty(), prop2 = new SigningTimeProperty();
        PropertiesSet instance = new PropertiesSet(1);
        instance.add(prop1);
        instance.add(prop2);
        instance.add(prop1);
    }

    /**
     * Test of remove method, of class PropertiesSet.
     */
    public void testRemove()
    {
        System.out.println("remove");
        SigningTimeProperty prop1 = new SigningTimeProperty();
        PropertiesSet instance = new PropertiesSet(1);
        instance.add(prop1);
        instance.remove(prop1);
        assertTrue(instance.isEmpty());
    }

    /**
     * Test of remove method, of class PropertiesSet.
     */
    @Test(expected = IllegalStateException.class)
    public void testRemoveNotPresent()
    {
        System.out.println("removeNotPresent");
        SigningTimeProperty prop1 = new SigningTimeProperty(), prop2 = new SigningTimeProperty();
        PropertiesSet instance = new PropertiesSet(1);
        instance.add(prop1);
        instance.remove(prop2);
    }

    /**
     * Test of isEmpty method, of class PropertiesSet.
     */
    @Test
    public void testIsEmpty()
    {
        System.out.println("isEmpty");

        SigningTimeProperty prop = new SigningTimeProperty();
        PropertiesSet instance = new PropertiesSet(1);
        assertTrue(instance.isEmpty());
        instance.add(prop);
        assertFalse(instance.isEmpty());
    }
    /**
     * Test of getProperties method, of class PropertiesSet.
     */
//    @Test
//    public void testGetProperties()
//    {
//        System.out.println("getProperties");
//        PropertiesSet instance = null;
//        Collection expResult = null;
//        Collection result = instance.getProperties();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
}
