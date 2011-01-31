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
package xades4j.properties;

import java.util.ArrayList;
import java.util.Collection;

/**
 *
 * @author Luís
 */
public class QualifyingProperties
{
    private final SignedProperties signedProperties;
    private final UnsignedProperties unsignedProperties;
    private Collection<QualifyingProperty> allProperties;

    public QualifyingProperties(
            SignedProperties signedProperties,
            UnsignedProperties unsignedProperties)
    {
        this.signedProperties = signedProperties;
        this.unsignedProperties = unsignedProperties;
        this.allProperties = null;
    }

    public SignedProperties getSignedProperties()
    {
        return signedProperties;
    }

    public UnsignedProperties getUnsignedProperties()
    {
        return unsignedProperties;
    }

    public Collection<QualifyingProperty> all()
    {
        if (null == allProperties)
        {
            allProperties = new ArrayList<QualifyingProperty>(signedProperties.getSigProps());
            allProperties.addAll(signedProperties.getDataObjProps());
            allProperties.addAll(unsignedProperties.getSigProps());
            allProperties.addAll(unsignedProperties.getDataObjProps());
        }
        return allProperties;
    }
}
