package xades4j.utils;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import xades4j.UnsupportedAlgorithmException;
import xades4j.algorithms.Algorithm;

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
}
