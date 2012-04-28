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

/**
 * A marshaller for parameters of a specific algorithm type. For each type of
 * algorithm (Java class) there has to be a corresponding marshaller.
 * <p>
 * The library has built-in marshallers for all the included algorithms.
 * @author Luís
 */
public interface AlgorithmParametersMarshaller<TAlgorithm extends Algorithm>
{
    /**
     * Marshals the parameters of a given {@code Algorithm}.
     * @param alg the algorithm whose parameters whill be marshalled
     * @param doc the document that will own the parameter nodes
     * @return the list of paramter nodes or {@code null} if none
     */
    List<Node> marshalParameters(TAlgorithm alg, Document doc);
}
