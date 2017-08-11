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

import java.util.ArrayList;
import java.util.Collection;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.HelperNodeList;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Utility methods for DOM nodes.
 * @author Luís
 */
public class DOMHelper
{
    private DOMHelper()
    {
    }

    /**
     * Gets the owner document of a node.
     *
     * @param node the node
     * @return the node's document or the node itself if it is a document node
     *
     * @throws NullPointerException if {@code node} is {@code null}
     */
    public static Document getOwnerDocument(Node node)
    {
        if (node.getNodeType() == Node.DOCUMENT_NODE)
            return (Document)node;
        return node.getOwnerDocument();
    }

    /**
     * Creates an element on the given document. Exceptions are as in {@link
     * Document#createElementNS(java.lang.String, java.lang.String)}. The qualified
     * name is obtained by {@code prefix}:{@code name} if the prefix is not {@code null}.
     *
     * @param doc the owner document
     * @param name the element's local name
     * @param prefix the element's prefix (may be {@code null})
     * @param namespaceURI the element's uri ({@code null} for no namespace)
     * @return the created element
     *
     * @see Document#createElementNS(java.lang.String, java.lang.String)
     */
    public static Element createElement(Document doc, String name,
            String prefix,
            String namespaceURI)
    {
        if (prefix != null)
            name = prefix + ":" + name;
        return doc.createElementNS(namespaceURI, name);
    }

    public static Element createElementInTempDocument(
            String name,
            String prefix,
            String namespaceURI)
    {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        try
        {
            Document doc = dbf.newDocumentBuilder().newDocument();
            return createElement(doc, name, prefix, namespaceURI);
        } catch (ParserConfigurationException ex)
        {
            return null;
        }
    }

    /**
     * Gets the first child element of a node.
     * @param node the node to get the child from
     * @return the first element child of {@code node} or {@code null} if none
     * @throws NullPointerException if {@code node} is {@code null}
     */
    public static Element getFirstChildElement(Node node)
    {
        node = node.getFirstChild();
        while (node != null && node.getNodeType() != Node.ELEMENT_NODE)
        {
            node = node.getNextSibling();
        }
        return (Element)node;
    }

    /**
     * Gets the last child element of a node.
     * @param node the node to get the child from
     * @return the last element child of {@code node} or {@code null} if none
     * @throws NullPointerException if {@code node} is {@code null}
     */
    public static Element getLastChildElement(Node node)
    {
        node = node.getLastChild();
        while (node != null && node.getNodeType() != Node.ELEMENT_NODE)
        {
            node = node.getPreviousSibling();
        }
        return (Element)node;
    }

    /**
     * Gets the next sibling of a node that is an element.
     * @param node the node
     * @return the next sibling element or {@code null} if none
     * @throws NullPointerException if {@code node} is {@code null}
     */
    public static Element getNextSiblingElement(Node node)
    {
        do
        {
            node = node.getNextSibling();
        } while (node != null && node.getNodeType() != Node.ELEMENT_NODE);

        return (Element)node;
    }

    /**
     * Gets the first element with the specified qualified name that is descendant
     * of {@code e}.
     * @param e the element
     * @param namespaceUri namespace
     * @param localName element name
     * @return the element or {@code null} if there is no such element
     */
    public static Element getFirstDescendant(
            Element e,
            String namespaceUri,
            String localName)
    {
        return (Element)e.getElementsByTagNameNS(namespaceUri, localName).item(0);
    }

    /**
     * Gets all the elements with the given qualified name that are direct children
     * of {@code e}.
     * @param e the element
     * @param namespaceURI namespace
     * @param localName element name
     * @return 
     */
    public static Collection<Element> getChildElementsByTagNameNS(Element e, String namespaceURI, String localName)
    {
        Node node = e.getFirstChild();
        Collection<Element> elements = new ArrayList<Element>();

        while (node != null)
        {
            if (node.getNodeType() == Node.ELEMENT_NODE && namespaceURI.equals(node.getNamespaceURI()) && localName.equals(node.getLocalName()))
            {
                elements.add((Element)node);
            }

            node = node.getNextSibling();
        }

        return elements;
    }
    
    public static NodeList nodeList(Iterable<Node> nodes)
    {
        HelperNodeList nl = new HelperNodeList();
        for (Node n : nodes)
        {
            nl.appendChild(n);
        }
        return nl;
    }

    /**
     * Sets the "Id" attribute of an element and sets it as the element's XML ID.
     * @param e the element where the ID should be set
     * @param id the id
     */
    public static void setIdAsXmlId(Element e, String id)
    {
        e.setAttributeNS(null, Constants._ATT_ID, id);
        e.setIdAttributeNS(null, Constants._ATT_ID, true);
    }

    /**
     * Defines the element's "Id" attribute as its XML ID, if present.
     * @param e the element
     */
    public static void useIdAsXmlId(Element e)
    {
        if(e.hasAttributeNS(null, Constants._ATT_ID))
        {
            e.setIdAttributeNS(null, Constants._ATT_ID, true);
        }
    }
}
