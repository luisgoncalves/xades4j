/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
