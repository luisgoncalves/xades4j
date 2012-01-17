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
package xades4j.utils;

import org.apache.xml.security.signature.Reference;
import org.w3c.dom.Node;

/**
 * Builder of inputs for time-stamps. The digests for time-stamps are usually
 * calculated over a concatenations of byte-streams, resulting from nodes and/or
 * {@code Reference}s (processed or not), with the proper canonicalization if needed.
 * This interface provides methods to build a sequential input by adding DOM {@code Node}s
 * or {@code Reference}s.
 * @author Luís
 */
public interface TimeStampDigestInput
{
    /**
     * Adds a {@code Reference} to the input. It is processed and the result is
     * canonicalized if it is a node-set.
     * @param r the reference to be added
     * @throws CannotAddDataToDigestInputException if there is an error adding the reference
     * @throws NullPointerException if {@code r} is {@code null}
     */
    void addReference(Reference r) throws CannotAddDataToDigestInputException;

    /**
     * Adds a {@code Node} to the input. The node is canonicalized.
     * @param n the node to be added
     * @throws CannotAddDataToDigestInputException if there is an error adding the node
     * @throws NullPointerException if {@code n} is {@code null}
     */
    void addNode(Node n) throws CannotAddDataToDigestInputException;

    /**
     * Gets the octet-stream corresponding to the actual state of the input.
     * @return the octet-stream (always a new instance)
     */
    byte[] getBytes();
}


