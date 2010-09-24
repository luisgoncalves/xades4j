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
package xades4j.production;

import xades4j.properties.DataObjectDesc;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * A reference to a signed data object. Each instance of this class will result
 * in a {@code ds:Reference} element in the signature.
 *
 * @see DataObjectDesc
 * @see EnvelopedXmlObject
 *
 * @author Luís
 */
public final class DataObjectReference extends DataObjectDesc
{
    private final String uri;

    /**
     * Creates a new data object reference. Additional information is added through
     * the different methods in {@link DataObjectDesc}.
     *
     * @param uri the URI that identifies the target data object
     *
     * @throws NullPointerException if {@code uri} is {@code null}
     * @throws IllegalArgumentException if {@code uri} is not RFC 2396 compliant
     */
    public DataObjectReference(String uri)
    {
        if (null == uri)
            throw new NullPointerException("Reference URI cannot be null");

        uri = uri.trim();

        try
        {
            new URI(uri);
        } catch (URISyntaxException e)
        {
            throw new IllegalArgumentException(e.getMessage());
        }
        this.uri = uri;
    }

    /**
     * Gets the uri of this data object reference
     * @return the uri that identifies the target data object
     */
    String getUri()
    {
        return uri;
    }
}
