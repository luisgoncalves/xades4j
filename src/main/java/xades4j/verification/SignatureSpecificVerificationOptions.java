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
package xades4j.verification;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import org.apache.xml.security.utils.resolver.ResourceResolver;

/**
 * Represents verification options that are specific to a signature, i.e., options
 * that are not profile-wide.
 *
 * @see xades4j.verification.XadesVerifier
 * @author Luís
 */
public class SignatureSpecificVerificationOptions
{

    private String baseUriForRelativeReferences;
    private InputStream dataForAnonymousReference;
    private final List<ResourceResolver> resolvers = new ArrayList<ResourceResolver>(0);

    /**
     * Sets the base URI to be used when resolving <b>all/b> the relative references.
     * Fragment references (starting with '#') are not afected.
     * @param baseUri the references' base uri
     * @return the current instance
     */
    public SignatureSpecificVerificationOptions useBaseUri(String baseUri)
    {
        this.baseUriForRelativeReferences = baseUri;
        return this;
    }

    String getBaseUri()
    {
        return this.baseUriForRelativeReferences;
    }

    /**
     * Sets the input stream to be used to resolve and verify a {@code null} URI
     * {@code ds:Reference}, if present. The stream is not closed.
     * @param data the input stream
     * @return the current instance
     */
    public SignatureSpecificVerificationOptions useDataForAnonymousReference(InputStream data)
    {
        this.dataForAnonymousReference = data;
        return this;
    }

    /**
     * Sets the data to be used to resolve and verify a {@code null} URI
     * {@code ds:Reference}, if present.
     * @param data the data
     * @return the current instance
     */
    public SignatureSpecificVerificationOptions useDataForAnonymousReference(byte[] data)
    {
        return this.useDataForAnonymousReference(new ByteArrayInputStream(data));
    }

    InputStream getDataForAnonymousReference()
    {
        return this.dataForAnonymousReference;
    }

    /**
     * Registers a {@link ResourceResolver} to be used when verifying the signature
     * The resolvers are considered in the same order they are added and have priority
     * over the globally registered resolvers.
     *
     * @param resolver the resolver
     * @return the current instance
     *
     * @throws NullPointerException if {@code resolver} is {@code null}
     */
    public SignatureSpecificVerificationOptions useResourceResolver(ResourceResolver resolver)
    {
        if (null == resolver)
        {
            throw new NullPointerException("Resolver cannot be null");
        }
        
        this.resolvers.add(resolver);
        return this;
    }

    List<ResourceResolver> getResolvers()
    {
        return this.resolvers;
    }
}
