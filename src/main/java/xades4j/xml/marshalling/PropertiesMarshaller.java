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
package xades4j.xml.marshalling;

import org.w3c.dom.Node;
import xades4j.properties.data.SigAndDataObjsPropertiesData;

/**
 * Interface for property data objects marshallers.
 * <p>
 * The signed and unsigned properties are marshalled at a different time in the
 * signature production. The separation comes from the nature of the properties:
 * signed properties need to be marshalled before the signature so that they are
 * covered by a {@code Reference}. On the other hand, unsigned properties do not
 * need to be marshalled before the signature and most of the times they can't be,
 * because they use information that results from the signature generation.
 * <p>
 * Built-in implementations of signed and unsigned properties data objects marshallers
 * are based on JAXB and support all the signed properties data objects in the library
 * (XAdES 1.4.1) plus the {@code GenericDOMData}.
 * @see SignedPropertiesMarshaller
 * @see UnsignedPropertiesMarshaller
 * @author Luís
 */
public interface PropertiesMarshaller
{
    /**
     * Marshal a pair of collections of property data objects (signature and signed
     * objects) into the {@code QualifyingProperties} node. Must create all the
     * DOM structure below {@code SignedProperties} or {@code UnsignedProperties},
     * inclusive.
     * @param props the data objects to be marshalled
     * @param qualifyingPropsNode the destination node
     * @throws MarshalException if there's an error
     */
    public void marshal(
            SigAndDataObjsPropertiesData props,
            Node qualifyingPropsNode) throws MarshalException;
}
