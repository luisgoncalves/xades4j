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
package xades4j.xml.marshalling.algorithms;

import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.TypeLiteral;
import com.google.inject.util.Types;
import java.lang.reflect.ParameterizedType;
import java.util.List;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import xades4j.algorithms.Algorithm;
import xades4j.UnsupportedAlgorithmException;

/**
 * @author Luís
 */
final class AlgorithmsParametersMarshallingProviderImpl implements AlgorithmsParametersMarshallingProvider
{
    private final Injector injector;

    @Inject
    public AlgorithmsParametersMarshallingProviderImpl(Injector injector)
    {
        this.injector = injector;
    }

    @Override
    public List<Node> marshalParameters(Algorithm alg, Document doc) throws UnsupportedAlgorithmException
    {
        AlgorithmParametersMarshaller marshaller;
        try
        {
            ParameterizedType pt = Types.newParameterizedType(AlgorithmParametersMarshaller.class, alg.getClass());
            marshaller = (AlgorithmParametersMarshaller) injector.getInstance(Key.get(TypeLiteral.get(pt)));
        } catch (RuntimeException ex)
        {
            throw new UnsupportedAlgorithmException("AlgorithmParametersMarshaller not available", alg.getUri(), ex);
        }

        List<Node> params = marshaller.marshalParameters(alg, doc);
        if (params != null && params.isEmpty())
        {
            throw new IllegalArgumentException(String.format("Parameter marshaller returned empty parameter list for algorithm %s", alg.getUri()));
        }
        return params;
    }
}
