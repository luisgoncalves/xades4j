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
import xades4j.XAdES4jException;

/**
 * Base for exceptions during certificate validation. Thrown when the subclasses
 * don't apply.
 * @see CannotBuildCertificationPathException
 * @see CannotSelectCertificateException
 * @author Luís
 */
public class CertificateValidationException extends XAdES4jException
{
    private final X509CertSelector certSelector;
    public CertificateValidationException(X509CertSelector s, String message)
    {
        super(message);
        this.certSelector = s;
    }

    public X509CertSelector getCertSelector()
    {
        return certSelector;
    }

}
