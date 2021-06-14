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
import java.util.Date;
import java.util.List;

import org.apache.xml.security.utils.resolver.ResourceResolverSpi;

/**
 * Represents verification options that are specific to a signature, i.e.,
 * options that are not profile-wide.
 * <p>
 * It includes base URI, data for anonymous references or resource resolvers
 *
 * @author Luís
 * @see xades4j.verification.XadesVerifier
 */
public class SignatureSpecificVerificationOptions
{
    static final SignatureSpecificVerificationOptions EMPTY = new SignatureSpecificVerificationOptions();

    private String baseUriForRelativeReferences;
    private boolean checkKeyUsage = true;
    private InputStream dataForAnonymousReference;
    private Date defaultVerificationDate = new Date();
    private final List<ResourceResolverSpi> resolvers = new ArrayList<ResourceResolverSpi>(0);
    private boolean followManifests = false;

    /**
     * Sets the base URI to be used when resolving <b>all</b> the relative
     * references. Fragment references (starting with '#') are not affected.
     *
     * @param baseUri the references' base URI
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

    protected boolean checkKeyUsage()
    {
        return checkKeyUsage;
    }

    /**
     * Configures whether to check that the keyUsage of the signer certificate
     * allows use for signing. If enabled (the default) signature validation will
     * fail if the keyUsage of the certificate does not allow signing.
     *
     * @param enabled {@code true} to enable the check, {@code false} to disable
     * @return the current instance
     */
    public SignatureSpecificVerificationOptions checkKeyUsage(boolean enabled)
    {
        this.checkKeyUsage = enabled;
        return this;
    }

    /**
     * Sets the input stream to be used to resolve and verify a {@code null} URI
     * {@code ds:Reference}, if present. The stream is not closed.
     *
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
     *
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
     * Registers a {@link ResourceResolverSpi} to be used when verifying the
     * signature The resolvers are considered in the same order they are added
     * and have priority over the globally registered resolvers.
     *
     * @param resolver the resolver
     * @return the current instance
     * @throws NullPointerException if {@code resolver} is {@code null}
     */
    public SignatureSpecificVerificationOptions useResourceResolver(ResourceResolverSpi resolver)
    {
        if (null == resolver)
        {
            throw new NullPointerException("Resolver cannot be null");
        }

        this.resolvers.add(resolver);
        return this;
    }

    List<ResourceResolverSpi> getResolvers()
    {
        return this.resolvers;
    }

    /**
     * Allow to specify a verification date for the signatures that are not
     * covered by timestamps.
     *
     * <p>
     * By default signatures not covered by timestamps are verified at the
     * current date ("now").
     * </p>
     *
     * @param verificationDate the default verification date. If null
     *                         {@code System.currentTime()} will be used
     * @return the current instance
     */
    public SignatureSpecificVerificationOptions setDefaultVerificationDate(Date verificationDate)
    {
        this.defaultVerificationDate = (verificationDate != null ? verificationDate : new Date());
        return this;
    }

    Date getDefaultVerificationDate()
    {
        return this.defaultVerificationDate;
    }

    /**
     * Defines whether {@code ds:Manifest}s referenced by the main signature {@code Reference}s should be automatically
     * validated.
     *
     * @param followManifests whether to follow manifests
     * @return the current instance
     */
    public SignatureSpecificVerificationOptions followManifests(boolean followManifests)
    {
        this.followManifests = followManifests;
        return this;
    }

    boolean isFollowManifests()
    {
        return followManifests;
    }
}
