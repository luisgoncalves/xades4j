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
package xades4j.providers;

import java.io.InputStream;
import xades4j.properties.ObjectIdentifier;

/**
 * Provider of signature policy documents. This is used to verify XAdES-EPES. By
 * default, no policies are supported, which means that if a {@code SignaturePolicyDocumentProvider}
 * is not supplied, the verification of XAdES-EPES (and only those) will fail.
 * @see xades4j.verification.XadesVerificationProfile
 * @author Luís
 */
public interface SignaturePolicyDocumentProvider
{
    /**
     * Gets a stream to the a policy document
     * @param sigPolicyId the identifier of the signature policy
     * @return the policy document stream or {@code null} if not available
     */
    public InputStream getSignaturePolicyDocumentStream(
            ObjectIdentifier sigPolicyId);
}
