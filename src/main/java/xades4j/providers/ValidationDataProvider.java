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
package xades4j.providers;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Provides the validation data that should be used to validate a signing certificate.
 * This is used for producing XAdES-C signatures.
 * @see xades4j.production.XadesCSigningProfile
 * @author Luís
 */
public interface ValidationDataProvider
{
    /**
     * Gets the validation data that should be used to validate a certificate.
     * @param certChainFragment the certificate that should be validated and
     *      possibly other certificates that are known to belong to the certification path
     * @return the validation data
     * @throws ValidationDataException if the validation data cannot be obtained
     */
    ValidationData getValidationData(List<X509Certificate> certChainFragment) throws ValidationDataException;
}
