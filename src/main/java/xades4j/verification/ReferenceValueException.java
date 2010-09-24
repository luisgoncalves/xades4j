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
package xades4j.verification;

import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;

/**
 * Thrown during signature verification when the core verification fails due to
 * reference validation.
 * @author Luís
 */
public class ReferenceValueException extends CoreVerificationException
{
    private final Reference reference;

    public ReferenceValueException(XMLSignature sig, Reference reference)
    {
        super(sig);
        this.reference = reference;
    }

    /**
     * Gets the reference that caused the validation error. If multiple references
     * are invalid, this is the first of them, in order of appearence.
     * @return the reference.
     */
    public Reference getReference()
    {
        return reference;
    }

    @Override
    public String getMessage()
    {
        return String.format("Reference '%s' cannot be validated", this.reference.getURI());
    }


}
