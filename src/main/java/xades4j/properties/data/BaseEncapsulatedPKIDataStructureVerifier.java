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

import java.util.Collection;

/**
 *
 * @author Luís
 */
class BaseEncapsulatedPKIDataStructureVerifier implements PropertyDataObjectStructureVerifier
{
    private final String propName;

    public BaseEncapsulatedPKIDataStructureVerifier(String propName)
    {
        this.propName = propName;
    }

    @Override
    public void verifyStructure(PropertyDataObject propData) throws PropertyDataStructureException
    {
        Collection<byte[]> data = ((BaseEncapsulatedPKIData)propData).getData();

        if (null == data || data.isEmpty())
            throw new PropertyDataStructureException("empty pki data list", propName);

        for (byte[] d : data)
        {
            if (null == d)
                throw new PropertyDataStructureException("null pki data", propName);
        }
    }
}
