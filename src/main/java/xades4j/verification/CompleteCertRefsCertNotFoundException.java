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

import java.security.cert.X509Certificate;

/**
 * Thrown during verification of the {@code CompleteCertificateRefs} property if
 * a reference for a certificate in the certification path is not found in the
 * property.
 * @author Luís
 */
public class CompleteCertRefsCertNotFoundException extends CompleteCertRefsVerificationException
{
    private final X509Certificate certificate;

    public CompleteCertRefsCertNotFoundException(X509Certificate certificate)
    {
        this.certificate = certificate;
    }

    /**
     * @return the certificate that caused the exception
     */
    public X509Certificate getCertificate()
    {
        return certificate;
    }

    @Override
    protected String getVerificationMessage()
    {
        return "cannot find a reference for certificate " + certificate.getSubjectX500Principal().getName();
    }
}
