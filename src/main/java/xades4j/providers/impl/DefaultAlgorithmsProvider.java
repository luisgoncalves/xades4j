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
import xades4j.UnsupportedAlgorithmException;

/**
 * @deprecated
 * This class is deprecated and might be removed in future versions.
 * @see DefaultAlgorithmsProviderEx
 * @author Luís
 */
public class DefaultAlgorithmsProvider implements AlgorithmsProvider
{
    private static final DefaultAlgorithmsProviderEx algorithmsProviderEx = new DefaultAlgorithmsProviderEx();

    @Override
    public String getSignatureAlgorithm(String keyAlgorithmName) throws UnsupportedAlgorithmException
    {
        return algorithmsProviderEx.getSignatureAlgorithm(keyAlgorithmName).getUri();
    }

    @Override
    public String getCanonicalizationAlgorithmForSignature()
    {
        return algorithmsProviderEx.getCanonicalizationAlgorithmForSignature().getUri();
    }

    @Override
    public String getCanonicalizationAlgorithmForTimeStampProperties()
    {
        return algorithmsProviderEx.getCanonicalizationAlgorithmForTimeStampProperties().getUri();
    }

    @Override
    public String getDigestAlgorithmForDataObjsReferences()
    {
        return algorithmsProviderEx.getDigestAlgorithmForDataObjsReferences();
    }

    @Override
    public String getDigestAlgorithmForReferenceProperties()
    {
        return algorithmsProviderEx.getDigestAlgorithmForReferenceProperties();
    }

    @Override
    public String getDigestAlgorithmForTimeStampProperties()
    {
        return algorithmsProviderEx.getDigestAlgorithmForTimeStampProperties();
    }

    @Override
    public String getCanonicalizationAlgorithmForKeyInfo()
    {
        return algorithmsProviderEx.getCanonicalizationAlgorithmForKeyInfo().getUri();
    }

    @Override
    public String getCanonicalizationAlgorithmForSignedProperties()
    {
        return algorithmsProviderEx.getCanonicalizationAlgorithmForSignedProperties().getUri();
    }
}
