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
package xades4j.verification;

import xades4j.properties.data.PropertyDataObject;

/**
 * Thrown during the verification of qualifyig properties if a verifier is not
 * found for one of the property data objects.
 * @see QualifyingPropertyVerifier
 * @see XadesVerificationProfile#withQualifyingPropertyVerifier(java.lang.Class, xades4j.verification.QualifyingPropertyVerifier)
 * @see XadesVerificationProfile#withQualifyingPropertyVerifier(java.lang.Class, java.lang.Class) 
 * @author Luís
 */
public class QualifyingPropertyVerifierNotAvailableException extends InvalidSignatureException
{
    private final String propDataClassName;

    public QualifyingPropertyVerifierNotAvailableException(
            PropertyDataObject propData)
    {
        propDataClassName = propData.getClass().getName();
    }

    /**
     * Gets the name of the Java class of the property data object that originated
     * the exception.
     * @return the class name
     */
    public String getPropDataClassName()
    {
        return propDataClassName;
    }


    @Override
    public String getMessage()
    {
        return "Property verifier not found for property data class " + propDataClassName;
    }
}
