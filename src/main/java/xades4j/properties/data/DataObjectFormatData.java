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
import xades4j.properties.ObjectIdentifier;

/**
 *
 * @author Luís
 */
public final class DataObjectFormatData implements PropertyDataObject
{
    /**/
    private final String objectRef;
    private String description, mimeType, encoding;
    private ObjectIdentifier identifier;
    private Collection<String> documentationUris;

    public DataObjectFormatData(String objectRef)
    {
        this.objectRef = objectRef;
    }

    public Collection<String> getDocumentationUris()
    {
        return documentationUris;
    }

    public void setDocumentationUris(Collection<String> documentationUris)
    {
        this.documentationUris = documentationUris;
    }

    public String getEncoding()
    {
        return encoding;
    }

    public void setEncoding(String encoding)
    {
        this.encoding = encoding;
    }

    public ObjectIdentifier getIdentifier()
    {
        return identifier;
    }

    public void setIdentifier(ObjectIdentifier identifier)
    {
        this.identifier = identifier;
    }

    public String getMimeType()
    {
        return mimeType;
    }

    public void setMimeType(String mimeType)
    {
        this.mimeType = mimeType;
    }

    public String getDescription()
    {
        return description;
    }

    public void setDescription(String description)
    {
        this.description = description;
    }

    public String getObjectRef()
    {
        return objectRef;
    }
}
