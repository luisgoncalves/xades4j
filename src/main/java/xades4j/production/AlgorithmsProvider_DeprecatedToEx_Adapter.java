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

import xades4j.algorithms.GenericAlgorithm;
import xades4j.algorithms.Algorithm;
import com.google.inject.Inject;
import xades4j.UnsupportedAlgorithmException;
import xades4j.providers.AlgorithmsProvider;
import xades4j.providers.AlgorithmsProviderEx;

/**
 * The AlgorithmsProvider interface has been deprecated. The lib now uses AlgorithmsProviderEx
 * internally. This class in an adapter used to register old implementations on
 * the signature profile.
 *
 * @author Luís
 */
class AlgorithmsProvider_DeprecatedToEx_Adapter implements AlgorithmsProviderEx
{

    private final AlgorithmsProvider algorithmsProvider;

    @Inject
    public AlgorithmsProvider_DeprecatedToEx_Adapter(AlgorithmsProvider algorithmsProvider)
    {
        this.algorithmsProvider = algorithmsProvider;
    }

    @Override
    public Algorithm getSignatureAlgorithm(String keyAlgorithmName) throws UnsupportedAlgorithmException
    {
        return new GenericAlgorithm(this.algorithmsProvider.getSignatureAlgorithm(keyAlgorithmName));
    }

    @Override
    public Algorithm getCanonicalizationAlgorithmForSignature()
    {
        return new GenericAlgorithm(this.algorithmsProvider.getCanonicalizationAlgorithmForSignature());
    }

    @Override
    public Algorithm getCanonicalizationAlgorithmForTimeStampProperties()
    {
        return new GenericAlgorithm(this.algorithmsProvider.getCanonicalizationAlgorithmForTimeStampProperties());
    }

    @Override
    public String getDigestAlgorithmForDataObjsReferences()
    {
        return this.algorithmsProvider.getDigestAlgorithmForDataObjsReferences();
    }

    @Override
    public String getDigestAlgorithmForReferenceProperties()
    {
        return this.algorithmsProvider.getDigestAlgorithmForReferenceProperties();
    }

    @Override
    public String getDigestAlgorithmForTimeStampProperties()
    {
        return this.algorithmsProvider.getDigestAlgorithmForTimeStampProperties();
    }
}



//class AlgorithmsProvider_DeprecatedToEx_ByType_Adapter implements AlgorithmsProviderEx{}
