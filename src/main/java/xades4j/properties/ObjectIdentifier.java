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

import xades4j.utils.StringUtils;

/**
 * An object identifier which may be an URI or an OID.
 * @see IdentifierType
 * @author Luís
 */
public class ObjectIdentifier
{
    private final String identifier;
    private final IdentifierType identifierType;
    private final String description;    

    public ObjectIdentifier(String identifier, IdentifierType identifierType, String description)
    {
        if(StringUtils.isNullOrEmptyString(identifier) || null == identifierType)
            throw new NullPointerException("Identifier and identifier type cannot be null");
        
        this.identifier = identifier;
        this.identifierType = identifierType;
        this.description = description;
    }

    public ObjectIdentifier(String identifier, IdentifierType identifierType)
    {
        this(identifier, identifierType, null);
    }

    public ObjectIdentifier(String identifier)
    {
        this(identifier, IdentifierType.URI);
    }

    public String getIdentifier()
    {
        return identifier;
    }

    public IdentifierType getIdentifierType()
    {
        return identifierType;
    }
    
    public String getDescription()
    {
        return description;
    }
}
