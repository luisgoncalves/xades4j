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

import java.security.cert.X509CRL;

/**
 * Thrown during the verification of the {@code CompleteRevocationRefs} property
 * if a CRL reference cannot be verified or is not found.
 * @author Luís
 */
public class CompleteRevocRefsReferenceException extends CompleteRevocRefsVerificationException
{
    private final X509CRL crl;
    private final String msg;

    public CompleteRevocRefsReferenceException(X509CRL crl, String msg)
    {
        this.crl = crl;
        this.msg = String.format("cannot verify reference for CRL issued by %s (%s)",
                crl.getIssuerX500Principal().getName(), msg);
    }

    public X509CRL getCrl()
    {
        return crl;
    }

    @Override
    protected String getVerificationMessage()
    {
        return this.msg;
    }
}
