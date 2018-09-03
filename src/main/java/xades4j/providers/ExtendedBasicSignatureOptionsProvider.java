/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2011 Luis Goncalves.
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

package xades4j.providers;

/**
 * Provides an extension for basic signature options such as whether {@code ds:KeyInfo} elements
 * should be included.
 *
 * A default implementation is provided.
 * @see xades4j.providers.impl.DefaultBasicSignatureOptionsProvider
 * 
 * @author Ismael
 */


public interface ExtendedBasicSignatureOptionsProvider extends BasicSignatureOptionsProvider{
	
	 /**
     * Disable {@code ds:X509SubjectName} in {@code ds:X509Certificate} 
     * element containing the signing certificate. This is only considered if
     * {@link #includeSigningCertificate()} returns {@code true}. 
     * @return {@code true} if the subjectName  should be disabled; false otherwise
     */
     boolean disableSubjectName();
    
    /**
     * Disable {@code ds:X509IssuerSerial} in {@code ds:X509Certificate} 
     * element containing the signing certificate. This is only considered if
     * {@link #includeSigningCertificate()} returns {@code true}.
     * @return {@code true} if the subjectName  should be disabled; false otherwise
     */
     boolean disableIssuerSerial();

}
