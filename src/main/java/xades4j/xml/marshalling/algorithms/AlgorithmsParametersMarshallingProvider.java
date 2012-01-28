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

import java.util.List;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import xades4j.algorithms.Algorithm;
import xades4j.UnsupportedAlgorithmException;

/**
 * Marshaller of parameters of any algorithm. It it responsible for finding and
 * invoking the appropriate parameters marshaller for each algorithm.
 * <p>
 * This interface is intended for use on internal components and <b> may be subject
 * to changes.</b>
 *
 * @author Luís
 */
public interface AlgorithmsParametersMarshallingProvider
{
    /**
     * @param alg the algorithm
     * @param doc the XML document where the nodes will be appended
     * @return the list os parameter nodes (can be {@code null but not empty)
     * @throws UnsupportedAlgorithmException if {@code alg} is not recognized
     */
    List<Node> marshalParameters(Algorithm alg, Document doc) throws UnsupportedAlgorithmException;
}
