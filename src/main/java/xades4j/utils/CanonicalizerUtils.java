package xades4j.utils;


import org.apache.xml.security.c14n.Canonicalizer;

import java.util.ArrayList;
import java.util.List;


/**
 * Provides some utility methods over Canonicalization Algorithms.
 * @author Emmanuelle
 */
public class CanonicalizerUtils
{
    private static final List<String> canonicalizationAlgorithms;

    static
    {
        canonicalizationAlgorithms = new ArrayList<String>();

        canonicalizationAlgorithms.add(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        canonicalizationAlgorithms.add(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);
        canonicalizationAlgorithms.add(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        canonicalizationAlgorithms.add(Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS);
        canonicalizationAlgorithms.add(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
        canonicalizationAlgorithms.add(Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS);
    }

    /**
     * Helper for determining if a URI is a Canonicalization Algorithm.
     *
     * @param uri String representing the URI to the W3C Canonicalization Algorithms.
     * @return boolean, true if URI is one of the W3C Canonicalization Algorithms.
     * @see <a href="https://www.w3.org/TR/xmlsec-algorithms/#canonicalization-uris">W3C Canonicalization Algorithms</a>
     */
    public static boolean isCanonicalizationAlgorithm(String uri)
    {
        return canonicalizationAlgorithms.contains(uri);
    }
}
