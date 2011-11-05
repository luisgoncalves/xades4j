/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2011 Luis Goncalves.
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

package xades4j.production;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

/**
 * This is just a proxy to the actual params marshallers. That's why it's named
 * "generator".
 * @author Luís
 */
interface DataObjectTransformParamsGenerator
{
    /**
     * Gets the node parameters for a given transform.
     * @param t the transform
     * @param doc the parent document
     * @return the list of parameter nodes
     */
    NodeList getParameters(DataObjectTransform t, Document doc);
}
