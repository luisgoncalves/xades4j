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

import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.XAdES4jException;
import xades4j.properties.DataObjectDesc;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Utility class to create enveloped signature. Enveloped signatures are ones whose
 * {@code Signature} element is child of the resource being signed. An appropriate
 * transform has to be used in these scenarios to exclude the signature element from
 * its own processing. This class is just an helper for those situations.
 * @author Luís
 */
public class Enveloped
{
    private final XadesSigner signer;

    /**
     * Creates a new instance based on the given {@code XadesSigner}.
     * @param signer the signer to be used by the resulting instance
     */
    public Enveloped(XadesSigner signer)
    {
        this.signer = signer;
    }

    /**
     * Creates an enveloped signature over an element. The element must have an
     * Id or be the document root if it doesn't. In the last case an empty (URI="")
     * reference is used.
     *
     * @param elementToSign the element that will be signed and will be the signature's parent
     *
     * @throws XAdES4jException see {@link XadesSigner#sign(xades4j.production.SignedDataObjects, org.w3c.dom.Node)}
     * @throws IllegalArgumentException if {@code elementToSign} doesn't have an Id and isn't the document root
     */
    public void sign(Element elementToSign) throws XAdES4jException
    {
        String refUri;
        if (elementToSign.hasAttribute("Id"))
            refUri = '#' + elementToSign.getAttribute("Id");
        else
        {
            if (elementToSign.getParentNode().getNodeType() != Node.DOCUMENT_NODE)
                throw new IllegalArgumentException("Element without Id must be the document root");
            refUri = "";
        }

        DataObjectDesc dataObjRef = new DataObjectReference(refUri).withTransform(new EnvelopedSignatureTransform());
        signer.sign(new SignedDataObjects(dataObjRef), elementToSign);
    }
}
