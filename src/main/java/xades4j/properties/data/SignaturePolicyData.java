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
    private final String locationUrl;

    public SignaturePolicyData(
            ObjectIdentifier identifier,
            String digestAlgorithm,
            byte[] digestValue,
            String locationUrl)
    {
        this.identifier = identifier;
        this.digestAlgorithm = digestAlgorithm;
        this.digestValue = digestValue;
        this.locationUrl = locationUrl;
    }

    public SignaturePolicyData()
    {
        this(null, null, null, null);
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

    public String getLocationUrl()
    {
        return locationUrl;
    }
}
