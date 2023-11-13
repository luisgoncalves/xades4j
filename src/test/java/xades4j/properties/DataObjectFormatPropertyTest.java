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

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Luís
 */
class DataObjectFormatPropertyTest
{
    /**
     * Test of withIdentifier method, of class DataObjectFormatProperty.
     */
    @Test
    void testWithIdentifier_String()
    {
        String uri = "uri";

        DataObjectFormatProperty instance = new DataObjectFormatProperty();
        instance.withIdentifier(uri);
        assertEquals(instance.getIdentifier().getIdentifier(), uri);

        instance.withIdentifier((ObjectIdentifier) null);
        assertNull(instance.getIdentifier());
    }

    /**
     * Test of withIdentifier method, of class DataObjectFormatProperty.
     */
    @Test
    void testWithIdentifier_String_IdentifierType()
    {
        String identifier = "uri";
        IdentifierType type = IdentifierType.URI;
        DataObjectFormatProperty instance = new DataObjectFormatProperty();

        instance.withIdentifier(identifier, type);

        assertEquals(identifier, instance.getIdentifier().getIdentifier());
        assertEquals(type, instance.getIdentifier().getIdentifierType());
    }

    /**
     * Test of withDocumentationUri method, of class DataObjectFormatProperty.
     */
    @Test
    void testWithDocumentationUri()
    {
        String documentationUri = "doc";
        DataObjectFormatProperty instance = new DataObjectFormatProperty();
        instance.withDocumentationUri(null);

        assertTrue(instance.getDocumentationUris().isEmpty());

        instance.withDocumentationUri(documentationUri);
        assertEquals(1, instance.getDocumentationUris().size());
    }

    /**
     * Test of withDocumentationUris method, of class DataObjectFormatProperty.
     */
    @Test
    void testWithDocumentationUris()
    {
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
    @Test
    void testWithDocumentationUris_Null()
    {
        DataObjectFormatProperty instance = new DataObjectFormatProperty();
        assertThrows(NullPointerException.class, () -> instance.withDocumentationUris(null));
    }
}
