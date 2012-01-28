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
package xades4j.algorithms;

import java.util.Set;
import org.apache.xml.security.c14n.Canonicalizer;

/**
 * The <a HREF="http://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/"> Exclusive
 * XML Canonicalization 1.0</a> <b>with</b> comments.
 * @see ExclusiveCanonicalXMLWithoutComments
 * @author Luís
 */
public final class ExclusiveCanonicalXMLWithComments extends ExclusiveCanonicalXML
{
    public ExclusiveCanonicalXMLWithComments(String... inclusiveNamespacePrefixes)
    {
        super(Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS, inclusiveNamespacePrefixes);
    }

    public ExclusiveCanonicalXMLWithComments(Set<String> inclusiveNamespacePrefixes)
    {
        super(Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS, inclusiveNamespacePrefixes);
    }
}
