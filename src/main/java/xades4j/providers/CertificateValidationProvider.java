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
 *
 * @author Luís
 * @see xades4j.providers.impl.PKIXCertificateValidationProvider
 * @see xades4j.verification.XadesVerificationProfile
 */
public interface CertificateValidationProvider
{
    /**
     * Validates the certificate identified by the given certificate selector and returns the resulting validation data
     * (certificate chain and possibly CRLs).
     * <p>
     * This method receives a set of certificates collected from the validation context that can be used to build the
     * acertification path. For instance, when verifying the signature's certificate, certificates collected from {@code KeyInfo}
     * are supplied; when verifying a timestamp token, the certificates contained on the timestamp token itself are supplied.
     * <p>
     * Additional certificates may be needed to build a certification path. This means that the provider must have access
     * to those additional certificates out of band.
     *
     * @param certSelector   identifies the intended leaf certificate for the current validation. This certificate may or
     *                       may not be available on the validation context (usually is). This selector is created using
     *                       information from the different {@code X509Data} elements within {@code KeyInfo}.
     * @param validationDate the time for which the validity of the certification path should be determined
     * @param otherCerts     a set of certificates that can be used to validate the leaf certificate, collected from the
     *                       validation context. May include the certificate that will be selected by {@code certSelector}.
     * @return the validation data resulting from the validation of the certificate selected by {@code certSelector}
     * @throws CertificateValidationException if the certificate cannot be validated (see subclasses of the exception)
     */
    ValidationData validate(
            X509CertSelector certSelector,
            Date validationDate,
            Collection<X509Certificate> otherCerts) throws CertificateValidationException, UnexpectedJCAException;
}
