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
package xades4j.utils;

import com.google.inject.Inject;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import xades4j.algorithms.Algorithm;
import xades4j.UnsupportedAlgorithmException;
import xades4j.xml.marshalling.algorithms.AlgorithmsParametersMarshallingProvider;

/**
 * @author Luís
 */
class TimeStampDigestInputFactoryImpl implements TimeStampDigestInputFactory
{
    private final AlgorithmsParametersMarshallingProvider parametersMarshallingProvider;

    @Inject
    TimeStampDigestInputFactoryImpl(AlgorithmsParametersMarshallingProvider parametersMarshallingProvider)
    {
        this.parametersMarshallingProvider = parametersMarshallingProvider;
    }

    @Override
    public TimeStampDigestInput newTimeStampDigestInput(Algorithm c14n) throws UnsupportedAlgorithmException
    {
        if (null == c14n)
        {
            throw new NullPointerException("Canonicalization algorithm cannot be null");
        }

        CanonicalizerUtils.checkC14NAlgorithm(c14n);

        return new TimeStampDigestInputImpl(c14n, this.parametersMarshallingProvider);
    }
}
