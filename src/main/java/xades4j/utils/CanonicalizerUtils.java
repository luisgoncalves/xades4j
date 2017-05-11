package xades4j.utils;

import java.util.List;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.transforms.InvalidTransformException;
import org.apache.xml.security.transforms.Transform;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import xades4j.UnsupportedAlgorithmException;
import xades4j.algorithms.Algorithm;
import xades4j.xml.marshalling.algorithms.AlgorithmsParametersMarshallingProvider;

/**
 * Provides some utility methods for Canonicalization.
 *
 * @author Emmanuelle
 */
public final class CanonicalizerUtils
{
    /**
     * Verifies input C14N Algorithm is in fact a C14N Algorithm by querying the
     * default Apache Canonicalizer.
     *
     * @param c14n - A C14N algorithm.
     * @throws UnsupportedAlgorithmException - If the URI is not registered in
     * the default Canonicalizer.
     */
    public static void checkC14NAlgorithm(Algorithm c14n) throws UnsupportedAlgorithmException
    {
        // HACK: since we're not using Canonicalizer, do a quick check to ensure
        // that 'c14n' refers to a configured C14N algorithm.
        try
        {
            Canonicalizer.getInstance(c14n.getUri());
        } catch (InvalidCanonicalizerException ex)
        {
            throw new UnsupportedAlgorithmException("Unsupported canonicalization method", c14n.getUri(), ex);
        }
    }

    /**
     * Creates a Transform for a given C14N algorithm.
     * @param c14n a C14N algorithm
     * @param parametersMarshallingProvider algorithm parameters marshaller.
     * @param doc the target XML document
     * @return the transform
     * @throws UnsupportedAlgorithmException if the C14N algorithm is not supported
     */
    public static Transform createTransform(Algorithm c14n, AlgorithmsParametersMarshallingProvider parametersMarshallingProvider, Document doc) throws UnsupportedAlgorithmException
    {
        List<Node> c14nParams = parametersMarshallingProvider.marshalParameters(c14n, doc);
        try
        {
            if (null == c14nParams)
            {
                return new Transform(doc, c14n.getUri());
            }
            else
            {
                return new Transform(doc, c14n.getUri(), DOMHelper.nodeList(c14nParams));
            }
        }
        catch (InvalidTransformException ex)
        {
            throw new UnsupportedAlgorithmException("C14N algorithm not supported in the XML Signature provider", c14n.getUri(), ex);
        }
    }
}
