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
     * @param certSelector the selector of the leaf certificate
     * @param validationDate the time for which the validity of the certification path should be determined
     * @param otherCerts a set of certificates that can be used to validate de leaf certificate.
     *      May include the certificate that will be selected with {@code certSelector}. May be {@code null}.
     * @return the validation data that validates the certificate selected by {@code certSelector}
     * @throws CertificateValidationException if the certificate cannot be validated (see subclasses of the exception)
     */
    ValidationData validate(
            X509CertSelector certSelector,
            Date validationDate,
            Collection<X509Certificate> otherCerts) throws CertificateValidationException, UnexpectedJCAException;
}
