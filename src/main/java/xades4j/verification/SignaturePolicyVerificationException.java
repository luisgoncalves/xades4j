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

import xades4j.properties.ObjectIdentifier;
import xades4j.properties.SignaturePolicyBase;

/**
 * Base for exceptions during verification of the {@code SignaturePolicyIdentifier}
 * property.
 * @author Luís
 */
public abstract class SignaturePolicyVerificationException extends InvalidPropertyException
{
    private final ObjectIdentifier signaturePolicyId;

    protected SignaturePolicyVerificationException(
            ObjectIdentifier signaturePolicyId)
    {
        this.signaturePolicyId = signaturePolicyId;
    }

    public ObjectIdentifier getSignaturePolicyId()
    {
        return signaturePolicyId;
    }

    @Override
    public final String getPropertyName()
    {
        return SignaturePolicyBase.PROP_NAME;
    }
}
