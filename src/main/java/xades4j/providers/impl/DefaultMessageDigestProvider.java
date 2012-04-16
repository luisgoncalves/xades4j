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
package xades4j.providers.impl;

import xades4j.providers.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.HashMap;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import xades4j.UnsupportedAlgorithmException;

/**
 * The default implementation of {@code MessageDigestEngineProvider}. It supports
 * the default digest algorithms in the Java platform, namely:
 * <ul>
 *  <li>{@code http://www.w3.org/2000/09/xmldsig#sha1} - SHA-1</li>
 *  <li>{@code http://www.w3.org/2001/04/xmlenc#sha256} - SHA-256</li>
 *  <li>{@code http://www.w3.org/2001/04/xmldsig-more#sha384} - SHA-384</li>
 *  <li>{@code http://www.w3.org/2001/04/xmlenc#sha512} - SHA-512</li>
 * </ul>
 * @author Luís
 */
public class DefaultMessageDigestProvider implements MessageDigestEngineProvider
{
    private static final HashMap<String, String> algorithmMapper;

    static
    {
        algorithmMapper = new HashMap<String, String>(4);
        algorithmMapper.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1, "SHA-1");
        algorithmMapper.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256, "SHA-256");
        algorithmMapper.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384, "SHA-384");
        algorithmMapper.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512, "SHA-512");
    }

    private final String messageDigestProvider;

    /**
     * Initializes a new instance that will use the specified JCE provider to get
     * MessageDigest instances.
     * @param messageDigestProvider the JCE provider for MessageDigest
     * @throws NoSuchProviderException if the JCE provider is not installed
     */
    public DefaultMessageDigestProvider(String messageDigestProvider) throws NoSuchProviderException
    {
        if(null == messageDigestProvider)
        {
            throw new NullPointerException("Message digest provider cannot be null");
        }

        if(Security.getProvider(messageDigestProvider) == null)
        {
            throw new NoSuchProviderException(messageDigestProvider);
        }

        this.messageDigestProvider = messageDigestProvider;
    }

    /**
     * Initializes a new instance that will get MessageDigests without specifying
     * a JCE provider.
     */
    public DefaultMessageDigestProvider()
    {
        this.messageDigestProvider = null;
    }

    @Override
    public MessageDigest getEngine(String digestAlgorithmURI) throws UnsupportedAlgorithmException
    {
        String digestAlgorithmName = algorithmMapper.get(digestAlgorithmURI);
        if (null == digestAlgorithmName)
            throw new UnsupportedAlgorithmException("Digest algorithm not supported by the provider", digestAlgorithmURI);
        try
        {
            return this.messageDigestProvider == null ? 
                MessageDigest.getInstance(digestAlgorithmName):
                MessageDigest.getInstance(digestAlgorithmName, this.messageDigestProvider);
        }
        catch (NoSuchAlgorithmException nsae)
        {
            throw new UnsupportedAlgorithmException(nsae.getMessage(), digestAlgorithmURI, nsae);
        }catch(NoSuchProviderException nspe)
        {
            // We checked that the provider existed on construction, but throw anyway
            throw new UnsupportedAlgorithmException("Provider not available", digestAlgorithmURI, nspe);
        }
    }
}
