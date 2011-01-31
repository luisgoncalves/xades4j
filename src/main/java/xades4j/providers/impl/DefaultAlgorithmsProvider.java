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
import java.util.HashMap;
import java.util.Map;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import xades4j.UnsupportedAlgorithmException;

/**
 * The default implementation of {@link AlgorithmsProvider}. The defaults
 * are:
 * <ul>
 *  <li>Signature: RSA(RSA_SHA256), DSA(DSA_SHA1)</li>
 *  <li>Canonicalization: Canonical XML 1.0 withouth comments</li>
 *  <li>Digest: SHA256 (data objs and refs properties); SHA1 (time-stamps)</li>
 * </ul>
 * Canonicalization and digest algorithms are the same for signature/references
 * and time-stamp properties.
 * @author Luís
 */
public class DefaultAlgorithmsProvider implements AlgorithmsProvider
{
    private static final Map<String, String> signatureAlgsMaps;

    static
    {
        signatureAlgsMaps = new HashMap<String, String>(2);
        signatureAlgsMaps.put("DSA", XMLSignature.ALGO_ID_SIGNATURE_DSA);
        signatureAlgsMaps.put("RSA", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
    }

    @Override
    public String getSignatureAlgorithm(String keyAlgorithmName) throws UnsupportedAlgorithmException
    {
        String sigAlg = signatureAlgsMaps.get(keyAlgorithmName);
        if (null == sigAlg)
            throw new UnsupportedAlgorithmException("Signature algorithm not supported by the provider", keyAlgorithmName);

        return sigAlg;
    }

    @Override
    public String getCanonicalizationAlgorithmForSignature()
    {
        return Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;
    }

    @Override
    public String getCanonicalizationAlgorithmForTimeStampProperties()
    {
        return getCanonicalizationAlgorithmForSignature();
    }

    @Override
    public String getDigestAlgorithmForDataObjsReferences()
    {
        return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256;
    }

    @Override
    public String getDigestAlgorithmForReferenceProperties()
    {
        return getDigestAlgorithmForDataObjsReferences();
    }

    @Override
    public String getDigestAlgorithmForTimeStampProperties()
    {
        return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1;
    }
}
