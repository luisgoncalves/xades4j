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
