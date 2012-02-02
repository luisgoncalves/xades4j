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

import xades4j.properties.ObjectIdentifier;

/**
 * Thrown during verification of the {@code SignaturePolicyIdentifier} property
 * if the digest of the policy document cannot be calculated (the algorithm is not
 * available).
 * @author Luís
 */
public class SignaturePolicyCannotDigestException extends SignaturePolicyVerificationException
{
    public SignaturePolicyCannotDigestException(ObjectIdentifier sigPolicyId, Throwable cause)
    {
        super(sigPolicyId, cause);
    }

    @Override
    protected String getVerificationMessage()
    {
        return "The signature policy document cannot be digested";
    }
}
