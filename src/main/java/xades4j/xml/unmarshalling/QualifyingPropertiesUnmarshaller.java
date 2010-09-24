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
package xades4j.xml.unmarshalling;

import org.w3c.dom.Element;

/**
 * Interface for unmarshallers of property data objects.
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
