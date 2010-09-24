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

import xades4j.properties.CommitmentTypePropertyBase;

/**
 * Thrown during verification of the {@code CommitmentTypeIndication} property if
 * it contains an object reference that doesn't match any {@code Reference} in the
 * signature.
 * @author Luís
 */
public class CommitmentTypeVerificationException extends InvalidPropertyException
{
    private final String unmatchedReference;

    public CommitmentTypeVerificationException(String unmatchedReference)
    {
        this.unmatchedReference = unmatchedReference;
    }

    public String getUnmatchedReference()
    {
        return unmatchedReference;
    }

    @Override
    protected String getVerificationMessage()
    {
        return String.format("The reference '%s' couldn't be resolved", unmatchedReference);
    }

    @Override
    public String getPropertyName()
    {
        return CommitmentTypePropertyBase.PROP_NAME;
    }
}
