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
import xades4j.properties.data.CertRef;

/**
 * Thrown during verification of the {@code SigningCertificate} property if the
 * validation of one of the certificate references fails.
 * @author Luís
 */
public class SigningCertificateReferenceException extends SigningCertificateVerificationException
{
    private final X509Certificate certificate;
    private final CertRef certificateRef;
    private final String msg;

    public SigningCertificateReferenceException(
            X509Certificate certificate,
            CertRef certificateRef,
            Throwable cause)
    {
        super(cause);
        this.certificate = certificate;
        this.certificateRef = certificateRef;
        this.msg = "cannot verify reference for certificate %s" + certificate.getSubjectX500Principal().getName();
    }

    public X509Certificate getCertificate()
    {
        return certificate;
    }

    public CertRef getCertificateRef()
    {
        return certificateRef;
    }

    @Override
    protected String getVerificationMessage()
    {
        return this.msg;
    }
}
