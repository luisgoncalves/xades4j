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

import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.PropertyDataObject;

/**
 * Verifies a property accordingly to the XAdES verification rules. The verifier
 * is passed the unmarshalled property data object (structure already verified)
 * and should verify the XAdES rules and create the high-level {@code QualifyingProperty}.
 * @param TData the type of data objects that the implementing class verifies
 * @author Luís
 */
public interface QualifyingPropertyVerifier<TData extends PropertyDataObject>
{
    /**
     * Verifies the property data and return the corresponding 'high-level'
     * property instance. In case of failure, an exception should be thrown. This
     * is done in order to prevent a failure to be undetected by erroneous code.
     * Furthermore, the data structures resulting for the verification process
     * become simpler.
     * 
     * @param propData the property data
     * @param ctx the context with data for validation
     * @return the verified QualifyingProperty (never {@code null})
     * @throws InvalidPropertyException (or subclasses) if the property validation fails
     */
    public QualifyingProperty verify(
            TData propData,
            QualifyingPropertyVerificationContext ctx) throws InvalidPropertyException;
}
