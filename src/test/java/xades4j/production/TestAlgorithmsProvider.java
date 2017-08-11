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

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import xades4j.algorithms.Algorithm;
import xades4j.UnsupportedAlgorithmException;
import xades4j.algorithms.CanonicalXMLWithoutComments;
import xades4j.algorithms.GenericAlgorithm;
import xades4j.providers.AlgorithmsProviderEx;

/**
 *
 * @author Luís
 */
class TestAlgorithmsProvider implements AlgorithmsProviderEx{

    @Override
    public Algorithm getSignatureAlgorithm(String keyAlgorithmName) throws UnsupportedAlgorithmException
    {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Algorithm getCanonicalizationAlgorithmForSignature()
    {
        return new CanonicalXMLWithoutComments();
    }

    @Override
    public Algorithm getCanonicalizationAlgorithmForTimeStampProperties()
    {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String getDigestAlgorithmForDataObjsReferences()
    {
        return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256;
    }

    @Override
    public String getDigestAlgorithmForReferenceProperties()
    {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String getDigestAlgorithmForTimeStampProperties()
    {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
