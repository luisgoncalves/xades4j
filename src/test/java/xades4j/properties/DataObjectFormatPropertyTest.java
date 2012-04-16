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

import java.util.ArrayList;
import java.util.Collection;
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
public class DataObjectFormatPropertyTest
{
    public DataObjectFormatPropertyTest()
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
     * Test of withIdentifier method, of class DataObjectFormatProperty.
     */
    @Test
    public void testWithIdentifier_String()
    {
        System.out.println("withIdentifier");
        String uri = "uri";

        DataObjectFormatProperty instance = new DataObjectFormatProperty();
        instance.withIdentifier(uri);
        assertEquals(instance.getIdentifier().getIdentifier(), uri);

        instance.withIdentifier((ObjectIdentifier)null);
        assertNull(instance.getIdentifier());
    }

    /**
     * Test of withIdentifier method, of class DataObjectFormatProperty.
     */
    public void testWithIdentifier_String_IdentifierType()
    {
        System.out.println("withIdentifier");
        String identifier = "uri";
        IdentifierType type = IdentifierType.URI;
        DataObjectFormatProperty instance = new DataObjectFormatProperty();

        instance.withIdentifier(identifier, type);

        assertEquals(identifier, instance.getIdentifier().getIdentifier());
        assertEquals(type, instance.getIdentifier().getIdentifierType());
    }

//    /**
//     * Test of withIdentifier method, of class DataObjectFormatProperty.
//     */
//    @Test(expected = NullPointerException.class)
//    public void testWithIdentifier_String_IdentifierType_Null()
//    {
//        System.out.println("withIdentifier");
//        String identifier = "uri";
//        DataObjectFormatProperty instance = new DataObjectFormatProperty();
//
//        instance.withIdentifier(identifier, null);
//    }

    /**
     * Test of withDocumentationUri method, of class DataObjectFormatProperty.
     */
    @Test
    public void testWithDocumentationUri()
    {
        System.out.println("withDocumentationUri");
        String documentationUri = "doc";
        DataObjectFormatProperty instance = new DataObjectFormatProperty();
        instance.withDocumentationUri(null);

        assertTrue(instance.getDocumentationUris().isEmpty());

        instance.withDocumentationUri(documentationUri);
        assertEquals(instance.getDocumentationUris().size(), 1);
    }

    /**
     * Test of withDocumentationUris method, of class DataObjectFormatProperty.
     */
    @Test
    public void testWithDocumentationUris()
    {
        System.out.println("withDocumentationUris");
        Collection<String> documentationUris = new ArrayList<String>(1);
        DataObjectFormatProperty instance = new DataObjectFormatProperty();

        instance.withDocumentationUris(documentationUris);
        assertTrue(instance.getDocumentationUris().isEmpty());

        documentationUris.add("doc");

        instance.withDocumentationUris(documentationUris);
        assertEquals(instance.getDocumentationUris().size(), 1);
    }

    /**
     * Test of withDocumentationUris method, of class DataObjectFormatProperty.
     */
    @Test(expected = NullPointerException.class)
    public void testWithDocumentationUris_Null()
    {
        System.out.println("withDocumentationUris");
        DataObjectFormatProperty instance = new DataObjectFormatProperty();
        instance.withDocumentationUris(null);
    }
}
