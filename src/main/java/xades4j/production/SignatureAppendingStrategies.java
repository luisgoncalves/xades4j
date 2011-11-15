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

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import xades4j.production.XadesSigner.SignatureAppendingStrategy;

/**
 *
 * @author Luís
 */
public class SignatureAppendingStrategies
{
    private SignatureAppendingStrategies()
    {
    }
    /**
     * The signature node should be appended as the first child of the reference
     * node (reference node is the parent).
     */
    public static final SignatureAppendingStrategy AsFirstChild = new AppendAsFirstChildStrategy();
    /**
     * The signature node should be appended as the last child of the reference
     * node (reference node is the parent).
     */
    public static final SignatureAppendingStrategy AsLastChild = new AppendAsLastChildStrategy();
    /**
     * The signature node should be appended as the previous sibling of the reference
     * node (reference node is a sibling).
     */
    public static final SignatureAppendingStrategy AsPreviousSibling = new AppendAsPreviousSiblingStrategy();
}

class AppendAsLastChildStrategy implements SignatureAppendingStrategy
{
    @Override
    public void append(Element signatureElement, Node referenceNode)
    {
        // Reference node is the parent
        referenceNode.appendChild(signatureElement);
    }

    @Override
    public void revert(Element signatureElement, Node referenceNode)
    {
        referenceNode.removeChild(signatureElement);
    }
}

class AppendAsFirstChildStrategy implements SignatureAppendingStrategy
{
    @Override
    public void append(Element signatureElement, Node referenceNode)
    {
        // Reference node is the parent
        Node currFirstChild = referenceNode.getFirstChild();
        referenceNode.insertBefore(signatureElement, currFirstChild);
    }

    @Override
    public void revert(Element signatureElement, Node referenceNode)
    {
        referenceNode.removeChild(signatureElement);
    }
}

class AppendAsPreviousSiblingStrategy implements SignatureAppendingStrategy
{
    @Override
    public void append(Element signatureElement, Node referenceNode)
    {
        // Reference node is the sibling
        Node parent = referenceNode.getParentNode();
        parent.insertBefore(signatureElement, referenceNode);
    }

    @Override
    public void revert(Element signatureElement, Node referenceNode)
    {
        Node parent = referenceNode.getParentNode();
        parent.removeChild(signatureElement);
    }
}
