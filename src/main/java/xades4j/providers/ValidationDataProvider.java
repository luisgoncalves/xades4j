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
