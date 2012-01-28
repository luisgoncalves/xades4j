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
import java.util.List;
import org.w3c.dom.Node;

/**
 * A representation of an algorithm for general purpose use. Before using this class
 * check if the library includes a specific {@link Algorithm} subclass for the needed
 * algorithm.
 * 
 * @author Luís
 */
public final class GenericAlgorithm extends Algorithm
{
    private final List<Node> params;

    /**
     * Creates a new instance. If any parameter nodes are supplied, they must
     * belong to the signature document.
     * @param uri the algorithm's URI
     * @param params the algorithm parameter nodes(optional)
     */
    public GenericAlgorithm(String uri, Node... params)
    {
        super(uri);
        this.params = params.length == 0 ? null : Arrays.asList(params);
    }

    /**
     * Creates a new instance. If any parameter nodes are supplied, they must
     * belong to the signature document.
     * @param uri the algorithm's URI
     * @param params the algorithm parameter nodes
     */
    public GenericAlgorithm(String uri, List<Node> params)
    {
        super(uri);
        this.params = params.isEmpty() ? null : Collections.unmodifiableList(params);
    }

    public List<Node> getParameters()
    {
        return this.params;
    }
}
