/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2011 Luis Goncalves.
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

import org.apache.xml.security.signature.XMLSignature;

/**
 * Interface for verifiers that are applied after signature unmarshalling and before
 * any actual verification.
 * <p>
 * Usages of {@code RawSignatureVerifier}s might include rejecting signatures with
 * more than a specific number of transforms on each data object reference and
 * signatures that use unsafe data object transforms.
 *
 * @see xades4j.verification.XadesVerificationProfile#withRawSignatureVerifier
 *
 * @author Luís
 */
public interface RawSignatureVerifier
{
    /**
     * The context for {@code RawSignatureVerifier}s.
     */
    public static class RawSignatureVerifierContext
    {
        private final XMLSignature signature;

        RawSignatureVerifierContext(XMLSignature signature)
        {
            this.signature = signature;
        }

        /**
         * Gets the unmarshalled XML signature for the current verification
         * @return the signature
         */
        public XMLSignature getSignature()
        {
            return this.signature;
        }
    }

    /**
     * Verifies the signature accordingly to this {@code RawSignatureVerifier}.
     * @param ctx the verification context
     * @throws InvalidSignatureExceptionif the signature is deemed invalid
     */
    void verify(RawSignatureVerifierContext ctx) throws InvalidSignatureException;
}
