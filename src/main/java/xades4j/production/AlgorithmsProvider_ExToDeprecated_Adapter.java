/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Luis Goncalves.
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

import com.google.inject.Inject;
import xades4j.UnsupportedAlgorithmException;
import xades4j.providers.AlgorithmsProvider;
import xades4j.providers.AlgorithmsProviderEx;

/**
 * Adapts the old AlgorithmsProvider to the new AlgorithmsProviderEx interface.
 * If the adaptee is configured with parameterized algorithms they will NOT be
 * considered; only their uri. Even though this will cause runtime errors, that
 * cannot happen with default implementations. If someone is using a different
 * AlgorithmsProviderEx and still depending on the old AlgorithmsProvider they will
 * have warnings because of the deprecation.
 * @author Luís
 */
final class AlgorithmsProvider_ExToDeprecated_Adapter implements AlgorithmsProvider
{
    private final AlgorithmsProviderEx adaptee;

    @Inject
    AlgorithmsProvider_ExToDeprecated_Adapter(AlgorithmsProviderEx adaptee)
    {
        this.adaptee = adaptee;
    }

    @Override
    public String getSignatureAlgorithm(String keyAlgorithmName) throws UnsupportedAlgorithmException
    {
        return this.adaptee.getSignatureAlgorithm(keyAlgorithmName).getUri();
    }

    @Override
    public String getCanonicalizationAlgorithmForSignature()
    {
        return this.adaptee.getCanonicalizationAlgorithmForSignature().getUri();
    }

    @Override
    public String getCanonicalizationAlgorithmForTimeStampProperties()
    {
        return this.adaptee.getCanonicalizationAlgorithmForTimeStampProperties().getUri();
    }

    @Override
    public String getDigestAlgorithmForDataObjsReferences()
    {
        return this.adaptee.getDigestAlgorithmForDataObjsReferences();
    }

    @Override
    public String getDigestAlgorithmForReferenceProperties()
    {
        return this.adaptee.getDigestAlgorithmForReferenceProperties();
    }

    @Override
    public String getDigestAlgorithmForTimeStampProperties()
    {
        return this.adaptee.getDigestAlgorithmForTimeStampProperties();
    }
}
