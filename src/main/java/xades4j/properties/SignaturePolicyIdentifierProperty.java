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
package xades4j.properties;

import xades4j.properties.ObjectIdentifier;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

/**
 * An explicit and unambiguous identifier of a signature policy.
 * @see SignaturePolicyBase
 * @author Luís
 */
public final class SignaturePolicyIdentifierProperty extends SignaturePolicyBase
{
    private final ObjectIdentifier identifier;
    private byte[] policyDocumentData;
    private InputStream policyDocumentStream;

    /**
     * @param identifier the policy identifier
     * @param policyDocumentStream an {@code InputStream} to the policy document
     * @throws NullPointerException if {@code policyDocumentStream} is {@code null}
     */
    public SignaturePolicyIdentifierProperty(
            ObjectIdentifier identifier,
            InputStream policyDocumentStream)
    {
        if (null == policyDocumentStream)
            throw new NullPointerException();

        this.identifier = identifier;
        this.policyDocumentStream = policyDocumentStream;
    }

    /**
     * @param identifier the policy identifier
     * @param policyDocumentData the content of the policy document
     * @throws NullPointerException if {@code policyDocumentData} is {@code null}
     */
    public SignaturePolicyIdentifierProperty(
            ObjectIdentifier identifier,
            byte[] policyDocumentData)
    {
        if (null == policyDocumentData)
            throw new NullPointerException();

        this.identifier = identifier;
        this.policyDocumentData = policyDocumentData;
    }

    /**
     * Gets the content of the policy document
     * @return the content or {@code null} if the instance was created with a stream
     */
    public byte[] getPolicyDocumentData()
    {
        return policyDocumentData;
    }

    /**
     * Gets the stream to the policy document. If the instance was created with
     * the policy document content, a ByteArrayInputStream is returned.
     * @return the stream
     */
    public InputStream getPolicyDocumentStream()
    {
        if (null == policyDocumentStream)
            policyDocumentStream = new ByteArrayInputStream(policyDocumentData);
        return policyDocumentStream;
    }

    public ObjectIdentifier getIdentifier()
    {
        return identifier;
    }
}
