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
import org.w3c.dom.Node;

/**
 * Represents content (tipically XML) that will be enveloped in the signature.
 * Each instance of this class will result in a {@code ds:Object} in the final
 * XAdES signature, which will contain the data. Also, this {@code Object} will
 * be covered by a {@code ds:Reference} so that it is actually included in the
 * signature.
 * 
 * <p>If one wants to add content other than XML, a text node can be used.
 *
 * @see DataObjectDesc
 * @see DataObjectReference
 *
 * @author Luís
 */
public final class EnvelopedXmlObject extends DataObjectDesc
{
    private final Node content;
    private final String mimeType, encoding;

    /**
     * Creates a new instance with the given context.
     * @param content the XML content
     *
     * @throws NullPointerException if {@code content} is {@code null}
     */
    public EnvelopedXmlObject(Node content)
    {
        this(content, null, null);
    }

    /**
     * Creates a new instance with the given content, mime type and encoding.
     * @param content the XML content
     * @param mimeType the mime type of the content (may be {@code null})
     * @param encoding the encoding of the content (may be {@code null})
     *
     * @throws NullPointerException if {@code content} is {@code null}
     */
    public EnvelopedXmlObject(Node content, String mimeType, String encoding)
    {
        if (null == content)
            throw new NullPointerException("Content node cannot be null");
        this.content = content;
        this.mimeType = mimeType;
        this.encoding = encoding;
    }

    /**
     * Gets the content of this object.
     * @return the content node (never {@code null})
     */
    Node getContent()
    {
        return content;
    }

    /**
     * Gets the encoding of the content.
     * @return the enconding or {@code null} if not specified
     */
    public String getEncoding()
    {
        return encoding;
    }

    /**
     * Gets the mime type of the content.
     * @return the mime type or {@code null} if not specified
     */
    public String getMimeType()
    {
        return mimeType;
    }
}
