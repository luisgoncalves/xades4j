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
package xades4j.verification;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.GenericDOMData;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author Luís
 */
public class GenericDOMDataVerifierTest
{
    private static Map<QName, QualifyingPropertyVerifier> customElemVerifiers;
    private static Document testDocument;

    @BeforeAll
    public static void setUpClass() throws Exception
    {
        customElemVerifiers = new HashMap<>(1);
        customElemVerifiers.put(new QName("http://test.generic.dom", "Elem"), new TestElemDOMVerifier());

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        testDocument = dbf.newDocumentBuilder().newDocument();
    }

    @Test
    void testVerify() throws Exception
    {
        GenericDOMData propData = new GenericDOMData(testDocument.createElementNS("http://test.generic.dom", "Elem"));
        QualifyingPropertyVerificationContext ctx = null;
        GenericDOMDataVerifier instance = new GenericDOMDataVerifier(customElemVerifiers);

        QualifyingProperty result = instance.verify(propData, ctx);
        assertEquals("Elem", result.getName());
    }

    @Test
    void testVerifyNoVerifier() throws Exception
    {
        GenericDOMData propData = new GenericDOMData(testDocument.createElementNS("http://test.generic.dom", "Elem"));
        QualifyingPropertyVerificationContext ctx = null;
        GenericDOMDataVerifier instance = new GenericDOMDataVerifier(new HashMap<QName, QualifyingPropertyVerifier>(0));

        assertThrows(InvalidPropertyException.class, () -> {
            instance.verify(propData, ctx);
        });
    }
}

class TestElemDOMVerifier implements QualifyingPropertyVerifier<GenericDOMData>
{
    @Override
    public QualifyingProperty verify(
            GenericDOMData propData,
            QualifyingPropertyVerificationContext ctx) throws InvalidPropertyException
    {
        return new QualifyingProperty()
        {
            @Override
            public boolean isSigned()
            {
                throw new UnsupportedOperationException("Not supported yet.");
            }

            @Override
            public boolean isSignature()
            {
                throw new UnsupportedOperationException("Not supported yet.");
            }

            @Override
            public String getName()
            {
                return "Elem";
            }
        };
    }
}
