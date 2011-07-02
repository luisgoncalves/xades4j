/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2011 Luis Goncalves.
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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import xades4j.properties.DataObjectDesc;

/**
 * A {@code null} URI data reference. An instance of this class will result in a
 * {@code ds:Reference} element in the signature whose {@code URI} attribute is
 * not present.
 * <p>
 * A signature can contain at most one reference of this type, as specified in
 * XML-DSIG.
 * 
 * @author Luís
 */
public final class AnonymousDataObjectReference extends DataObjectDesc
{

    private final InputStream dataStream;

    /**
     * Creates a new anonymous data object reference from a data stream. The stream
     * will be accessed at {@code ds:Reference} generation and won't be closed.
     * Additional information is added through the different methods in {@link DataObjectDesc}.
     *
     * @param dataStream the input stream used to get the object data
     *
     * @throws NullPointerException if {@code dataStream} is {@code null}
     */
    public AnonymousDataObjectReference(InputStream dataStream)
    {
        if (null == dataStream)
        {
            throw new NullPointerException("Data stream cannot be null");
        }
        this.dataStream = dataStream;
    }

    /**
     * Creates a new anonymous data object reference. Additional information is
     * added through the different methods in {@link DataObjectDesc}.
     *
     * @param data the object data
     *
     * @throws NullPointerException if {@code data} is {@code null}
     */
    public AnonymousDataObjectReference(byte[] data)
    {
        this(new ByteArrayInputStream(data));
    }

    InputStream getDataStream()
    {
        return dataStream;
    }
}
