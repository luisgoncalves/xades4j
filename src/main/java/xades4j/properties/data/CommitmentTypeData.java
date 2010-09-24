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
}
