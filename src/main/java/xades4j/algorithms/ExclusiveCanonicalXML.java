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

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/**
 * Base class for representations of the <a HREF="http://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">
 * Exclusive XML Canonicalization 1.0</a>.
 * @author Luís
 */
public abstract class ExclusiveCanonicalXML extends Algorithm{

    private final Set<String> inclusiveNamespacePrefixes;

    protected ExclusiveCanonicalXML(String uri, String... inclusiveNamespacePrefixes)
    {
        this(uri, new TreeSet<String>(Arrays.asList(inclusiveNamespacePrefixes)));
    }

    protected ExclusiveCanonicalXML(String uri, Set<String> inclusiveNamespacePrefixes)
    {
        super(uri);
        this.inclusiveNamespacePrefixes = Collections.unmodifiableSet(inclusiveNamespacePrefixes);
    }

    /**
     * Gets the inclusive namespace prefixes.
     *
     * @return an unmodifiable Set with the prefixes
     */
    public Set<String> getInclusiveNamespacePrefixes()
    {
        return inclusiveNamespacePrefixes;
    }


}
