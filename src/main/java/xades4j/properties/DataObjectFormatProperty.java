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

import java.util.Collection;
import xades4j.utils.CollectionUtils;

/**
 * Represents the DataObjectFormat signed data object property. The DataObjectFormat
 * element provides information that describes the format of the signed data object.
 * When presenting signed data to a human user it may be important that there is
 * no ambiguity as to the presentation of the signed data object to the relying
 * party. In order for the appropriate representation (text, sound or video) to
 * be selected by the relying party a content hint may be indicated by the signer.
 * <p>
 * A XAdES signature may contain more than one {@code DataObjectFormat} elements,
 * each one qualifying one signed data object.
 * <p>
 * This property is associated with the corresponding data object via the
 * {@link DataObjectDesc#withDataObjectFormat(xades4j.properties.DataObjectFormatProperty)
 * withDataObjectFormat} method of the {@link DataObjectDesc} class.
 *
 * @author Luís
 */
public class DataObjectFormatProperty extends SignedDataObjectProperty
{
    public static final String PROP_NAME = "DataObjectFormat";
    /**/
    private final String mimeType, encoding;
    private String description;
    private ObjectIdentifier identifier;
    private Collection<String> documentationUris;

    public DataObjectFormatProperty(String mimeType)
    {
        this(mimeType, null);
    }

    public DataObjectFormatProperty(String mimeType, String encoding)
    {
        super(TargetMultiplicity.ONE);
        this.mimeType = mimeType;
        this.encoding = encoding;
    }

    public DataObjectFormatProperty()
    {
        this(null, null);
    }

    public DataObjectFormatProperty withIdentifier(ObjectIdentifier identifier)
    {
        this.identifier = identifier;
        return this;
    }

    public DataObjectFormatProperty withIdentifier(String identifier,
            IdentifierType identifierType)
    {
        return withIdentifier(new ObjectIdentifier(identifier, identifierType));
    }

    public DataObjectFormatProperty withIdentifier(String identifier)
    {
        return withIdentifier(new ObjectIdentifier(identifier));
    }

    public DataObjectFormatProperty withDescription(String description)
    {
        this.description = description;
        return this;
    }

    public DataObjectFormatProperty withDocumentationUri(String documentationUri)
    {
        if (null != documentationUri)
            getOrCreateDocumentationUrisList().add(documentationUri);
        return this;
    }

    public DataObjectFormatProperty withDocumentationUris(
            Collection<String> documentationUris)
    {
        if (null == documentationUris)
            throw new NullPointerException("Uri list is null");

        if (!documentationUris.isEmpty())
            getOrCreateDocumentationUrisList().addAll(documentationUris);
        return this;
    }

    private Collection<String> getOrCreateDocumentationUrisList()
    {
        documentationUris = CollectionUtils.newIfNull(documentationUris, 2);
        return documentationUris;
    }

    public Collection<String> getDocumentationUris()
    {
        return CollectionUtils.emptyIfNull(documentationUris);
    }

    public String getMimeType()
    {
        return mimeType;
    }

    public String getEncoding()
    {
        return encoding;
    }

    public String getDescription()
    {
        return description;
    }

    public ObjectIdentifier getIdentifier()
    {
        return identifier;
    }

    @Override
    public String getName()
    {
        return PROP_NAME;
    }
}
