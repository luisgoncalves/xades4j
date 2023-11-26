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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import xades4j.algorithms.Algorithm;
import xades4j.algorithms.GenericAlgorithm;
import xades4j.algorithms.XPath2FilterTransform;
import xades4j.algorithms.XPath2FilterTransform.XPath2Filter;
import xades4j.algorithms.XPathTransform;
import xades4j.utils.SignatureServicesTestBase;

/**
 * @author Luís
 */
class DataObjectDescTest
{
    @Test
    void testWithTransform() throws Exception
    {
        Document doc = SignatureServicesTestBase.getNewDocument();
        DataObjectDesc instance = new DataObjectDescTestImpl()
                .withTransform(new XPathTransform("xpath"))
                .withTransform(XPath2Filter.subtract("xpath1").intersect("xpath2"))
                .withTransform(new GenericAlgorithm("uri", doc.createElement("param1"), doc.createElement("param2")));

        Algorithm[] transforms = instance.getTransforms().toArray(new Algorithm[0]);

        assertEquals(3, transforms.length);
        assertEquals(XPathTransform.class, transforms[0].getClass());
        assertEquals(XPath2FilterTransform.class, transforms[1].getClass());
        assertEquals(GenericAlgorithm.class, transforms[2].getClass());
    }

    @Test
    void testWithDataObjectFormatRepeatedInstance()
    {
        DataObjectFormatProperty format = new DataObjectFormatProperty();
        DataObjectDesc instance = new DataObjectDescTestImpl();

        instance.withDataObjectFormat(format);

        assertThrows(IllegalStateException.class, () -> instance.withDataObjectFormat(format));
    }

    /**
     * Test of withDataObjectFormat method, of class DataObjectDesc.
     */
    @Test
    @Disabled("test is failing")
    void testWithDataObjectFormatMultipleTargets()
    {
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
    void testWithCommitmentType()
    {
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
    void testHasProperties()
    {
        DataObjectDesc instance = new DataObjectDescTestImpl();
        assertFalse(instance.hasProperties());

        instance.withDataObjectFormat(new DataObjectFormatProperty());
        assertTrue(instance.hasProperties());
    }

    /**
     * Test of getSignedDataObjProps method, of class DataObjectDesc.
     */
    @Test
    void testGetSignedDataObjProps()
    {
        DataObjectDesc instance = new DataObjectDescTestImpl();
        assertEquals(0, instance.getSignedDataObjProps().size());

        instance.withDataObjectFormat(new DataObjectFormatProperty());
        assertEquals(1, instance.getSignedDataObjProps().size());
    }

    public static class DataObjectDescTestImpl extends DataObjectDesc
    {
    }
}
