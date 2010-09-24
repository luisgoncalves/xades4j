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
 * Default implementations of signed and unsigned properties data objects marshallers
 * are supplied.
 * @see DefaultSignedPropertiesMarshaller
 * @see DefaultUnsignedPropertiesMarshaller
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
     * @param propsId the identifier to be set on the top-most property container ({@code SignedProperties} or {@code UnsignedProperties})
     * @param qualifyingPropsNode the destination node
     * @throws MarshalException if there's an error
     */
    public void marshal(
            SigAndDataObjsPropertiesData props,
            String propsId,
            Node qualifyingPropsNode) throws MarshalException;
}
