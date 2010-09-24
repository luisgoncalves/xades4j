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
package xades4j.properties.data;

import xades4j.properties.ObjectIdentifier;

/**
 *
 * @author Luís
 */
public final class SignaturePolicyData implements PropertyDataObject
{
    private final ObjectIdentifier identifier;
    private final String digestAlgorithm;
    private final byte[] digestValue;

    public SignaturePolicyData(
            ObjectIdentifier identifier,
            String digestAlgorithm,
            byte[] digestValue)
    {
        this.identifier = identifier;
        this.digestAlgorithm = digestAlgorithm;
        this.digestValue = digestValue;
    }

    public SignaturePolicyData()
    {
        this.identifier = null;
        this.digestAlgorithm = null;
        this.digestValue = null;
    }

    public String getDigestAlgorithm()
    {
        return digestAlgorithm;
    }

    public byte[] getDigestValue()
    {
        return digestValue;
    }

    public ObjectIdentifier getIdentifier()
    {
        return identifier;
    }
}
