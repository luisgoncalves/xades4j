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
