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
package xades4j.production;

import xades4j.properties.DataObjectDesc;
import java.net.URI;

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
    private String type;

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
        {
            throw new NullPointerException("Reference URI cannot be null");
        }

        uri = uri.trim();
        URI.create(uri.trim());
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

    /**
     * Defines the {@code type} of the reference.
     * <p>
     * "The <b>optional</b> Type attribute contains information about the type of object
     * being signed after all {@code ds:Reference} transforms have been applied.
     * This is represented as a URI."
     * <p>
     * "The Type attribute applies to the item being pointed at, not its contents."
     * @param type the referece's type
     * @return the current instance
     */
    public DataObjectReference withType(String type)
    {
        this.type = type;
        return this;
    }

    String getType()
    {
        return type;
    }
}
