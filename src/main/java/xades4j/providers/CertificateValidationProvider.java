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

import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import xades4j.verification.UnexpectedJCAException;

/**
 * Provides validation of certificates.
 * @see xades4j.providers.impl.PKIXCertificateValidationProvider
 * @see xades4j.verification.XadesVerificationProfile
 * @author Luís
 */
public interface CertificateValidationProvider
{
    /**
     *
     * @param certSelector the selector of the leaf certificate, created using information
     *      from a {@code X509Data} element within {@code KeyInfo}
     *      data on {@code KeyInfo}
     * @param validationDate the time for which the validity of the certification path should be determined
     * @param otherCerts a set of certificates that can be used to validate de leaf
     *      certificate, collected from {@code KeyInfo}. May include the certificate
     *      that will be selected with {@code certSelector}. May be {@code null}
     * @return the validation data that validates the certificate selected by {@code certSelector}
     * @throws CertificateValidationException if the certificate cannot be validated (see subclasses of the exception)
     */
    ValidationData validate(
            X509CertSelector certSelector,
            Date validationDate,
            Collection<X509Certificate> otherCerts) throws CertificateValidationException, UnexpectedJCAException;
}
