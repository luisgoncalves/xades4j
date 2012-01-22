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
package xades4j.xml.unmarshalling;

import org.w3c.dom.Element;

/**
 * Interface for unmarshallers of property data objects.
 * <p>
 * Built-in implementation is based on JAXB and supports all the unsigned properties
 * data objects up to XAdES-C, except {@code SignerRole} and attributes validation
 * data properties.
 * @author Luís
 */
public interface QualifyingPropertiesUnmarshaller
{
    /**
     * Indicates if unknown unsigend properties should be accepted. If so, they
     * should be returned with instances of {@code GenericDOMData}.
     * @param accept {@code true} if unknown properties should be accepted
     */
    public void setAcceptUnknownProperties(boolean accept);

    /**
     * Unmarshal the properties in the given {@code QualifyingProperties} node.
     * The resulting property data objects should be added to the collector.
     * @param qualifyingProps the qualifying properties element
     * @param propertyDataCollector the collector of property data objects
     * @throws UnmarshalException if there's an error (may be {@link PropertyUnmarshalException})
     */
    public void unmarshalProperties(
            Element qualifyingProps,
            QualifyingPropertiesDataCollector propertyDataCollector) throws UnmarshalException;
}
