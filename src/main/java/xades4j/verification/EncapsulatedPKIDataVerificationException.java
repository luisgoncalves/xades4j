/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Hubert Kario - QBS.
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

import java.security.cert.CertificateException;

public class EncapsulatedPKIDataVerificationException extends InvalidPropertyException
{
    private static final long serialVersionUID = 1L;
    private final String propName;

    public EncapsulatedPKIDataVerificationException(CertificateException ex, String propName)
    {
        super(ex);
        this.propName = propName;
    }

    @Override
    protected String getVerificationMessage()
    {
        return "Verification failure, can't parse certificates";
    }

    @Override
    public String getPropertyName()
    {
        return propName;
    }

}
