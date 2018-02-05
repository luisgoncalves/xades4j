/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2017 Luis Goncalves.
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

import java.util.Collections;
import java.util.List;
import org.apache.xml.security.transforms.InvalidTransformException;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import xades4j.UnsupportedAlgorithmException;
import xades4j.algorithms.Algorithm;
import xades4j.xml.marshalling.algorithms.AlgorithmsParametersMarshallingProvider;

/**
 *
 * @author luis
 */
public final class TransformUtils
{
    /**
     * Creates a Transform element for a given algorithm.
     * @param algorithm algorithm
     * @param parametersMarshallingProvider algorithm parameters marshaller
     * @param document the target XML document
     * @return the Transform
     * @throws UnsupportedAlgorithmException if the algorithm is not supported
     */
    public static Transform createTransform(Algorithm algorithm, AlgorithmsParametersMarshallingProvider parametersMarshallingProvider, Document document) throws UnsupportedAlgorithmException
    {
        List<Node> params = parametersMarshallingProvider.marshalParameters(algorithm, document);
        try
        {
            if (null == params)
            {
                return new Transform(document, algorithm.getUri());
            }
            else
            {
                return new Transform(document, algorithm.getUri(), DOMHelper.nodeList(params));
            }
        }
        catch (InvalidTransformException ex)
        {
            throw new UnsupportedAlgorithmException("C14N algorithm not supported in the XML Signature provider", algorithm.getUri(), ex);
        }
    }
    
    /**
     * Creates a Transforms element for a given set of algorithms
     * @param document the target XML document
     * @param algorithmsParametersMarshaller algorithm parameters marshaller
     * @param algorithms algorithms
     * @return the Transforms
     * @throws UnsupportedAlgorithmException if an algorithm is not supported
     */
    public static Transforms createTransforms(
            Document document,
            AlgorithmsParametersMarshallingProvider algorithmsParametersMarshaller,
            Iterable<Algorithm> algorithms) throws UnsupportedAlgorithmException
    {
        Transforms transforms = new Transforms(document);

        for (Algorithm t : algorithms)
        {
            try
            {
                List<Node> params = algorithmsParametersMarshaller.marshalParameters(t, document);
                if (null == params)
                {
                    transforms.addTransform(t.getUri());
                }
                else
                {
                    transforms.addTransform(t.getUri(), DOMHelper.nodeList(params));
                }
            }
            catch (TransformationException ex)
            {
                throw new UnsupportedAlgorithmException(
                        "Unsupported transform on XML Signature provider",
                        t.getUri(), ex);
            }
        }
        return transforms;
    }
    
    /**
     * Creates a Transforms element for a given algorithm
     * @param algorithm algorithm
     * @param algorithmsParametersMarshaller algorithm parameters marshaller
     * @param document the target XML document
     * @return the Transforms
     * @throws UnsupportedAlgorithmException if an algorithm is not supported
     */
    public static Transforms createTransforms(
            Algorithm algorithm,
            AlgorithmsParametersMarshallingProvider algorithmsParametersMarshaller,
            Document document) throws UnsupportedAlgorithmException
    {
        return createTransforms(document, algorithmsParametersMarshaller, Collections.singleton(algorithm));
    }
}
