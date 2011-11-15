/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
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

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import xades4j.XAdES4jException;

/**
 * Interface for a producer of signatures. The features of the produced signatures
 * depend on the profile configuration.
 * <p>
 * All the exceptions defined in the current package may be thrown during production.
 * They are organized as a tree which means that one can go from rough to fine-grained
 * handling by catching exceptions in the different branches/depths of the tree.
 * 
 * @see XadesSigningProfile
 * @author Luís
 */
public interface XadesSigner
{
    /**
     * Applies a signature over a set of data objects and appends it to the given
     * node.
     * @param signedDataObjects the data objects to be signed
     * @param parent the node to which the signature element will be appended
     * @return the signature result
     * @see SignedDataObjects
     * @throws XAdES4jException if an error occurs
     */
    public XadesSignatureResult sign(
            SignedDataObjects signedDataObjects,
            Node parent) throws XAdES4jException;

    /**
     * A strategy to append the signature element to a document's DOM tree using
     * a given node as reference. Examples are appending the signature as the first
     * or last child of a node.
     * @see SignatureAppendingStrategies
     */
    public interface SignatureAppendingStrategy
    {
        /**
         * Appends the signature element to the DOM tree using the given node as
         * reference.
         * @param signatureElement the signature element
         * @param referenceNode the reference node
         */
        void append(Element signatureElement, Node referenceNode);

        /**
         * Reverts the append action. Used when to remove the signature from the
         * DOM tree when signature production fails.
         * @param signatureElement the signature element
         * @param referenceNode the reference node
         */
        void revert(Element signatureElement, Node referenceNode);
    }

    /**
     * Applies a signature over a set of data objects and appends it to the DOM
     * tree using the given srtategy and reference node.
     * @param signedDataObjects the data objects to be signed
     * @param referenceNode the node used as reference for the appending strategy
     * @param appendingStrategy the appending strategy
     * @return the signature result
     * @see SignedDataObjects
     * @see SignatureAppendingStrategies
     * @throws XAdES4jException if an error occurs
     */
    public XadesSignatureResult sign(
            SignedDataObjects signedDataObjects,
            Node referenceNode,
            SignatureAppendingStrategy appendingStrategy) throws XAdES4jException;
}
