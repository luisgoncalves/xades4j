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
import xades4j.utils.CollectionUtils;

/**
 *
 * @author Luís
 */
public final class CommitmentTypeData implements PropertyDataObject
{
    private String description, uri;
    private Collection<String> objReferences;
    private Collection qualifiers;

    public CommitmentTypeData(String uri)
    {
        this(uri, null);
    }

    public CommitmentTypeData(String uri, String description)
    {
        this.uri = uri;
        this.description = description;
    }

    public String getDescription()
    {
        return description;
    }

    public void setDescription(String description)
    {
        this.description = description;
    }

    public Collection<String> getObjReferences()
    {
        return objReferences;
    }

    public void setObjReferences(Collection<String> objReferences)
    {
        this.objReferences = objReferences;
    }

    public void addObjReferences(String objRef)
    {
        this.objReferences = CollectionUtils.newIfNull(objReferences, 2);
        this.objReferences.add(objRef);
    }

    public String getUri()
    {
        return uri;
    }
    
    public void setQualifiers(Collection qualifiers){
        this.qualifiers = qualifiers;
    }
    
    public Collection getQualifiers(){
        return this.qualifiers;
    }
}
