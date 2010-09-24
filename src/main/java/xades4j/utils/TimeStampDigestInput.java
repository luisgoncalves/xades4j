/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA
 */
package xades4j.utils;

import java.io.ByteArrayOutputStream;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transform;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

/**
 * Helper class to build inputs for time-stamps. The digests for time-stamps are
 * usually calculated over a concatenations of byte-streams, resulting from nodes
 * and/or processed {@code Reference}s, with the proper canonicalization if needed.
 * This class provides methods to build a sequential input by adding DOM {@code Node}s
 * or {@code Reference}s.
 * @author Luís
 */
public class TimeStampDigestInput
{
    private final String canonMethodUri;
    private final ByteArrayOutputStream digestInput;

    /**
     *
     * @param canonMethodUri the canonicalization method to be used, if needed
     * @throws NullPointerException if {@code canonMethodUri} is {@code null}
     */
    public TimeStampDigestInput(String canonMethodUri)
    {
        if (null == canonMethodUri)
            throw new NullPointerException();

        this.canonMethodUri = canonMethodUri;
        this.digestInput = new ByteArrayOutputStream();
    }

    /**
     * Adds a {@code Reference} to the input. It is processed and the result is
     * canonicalized if it is a node-set.
     * @param r the reference to be added
     * @throws CannotAddDataToDigestInputException if there is an error adding the reference
     * @throws NullPointerException if {@code r} is {@code null}
     */
    public void addReference(Reference r) throws CannotAddDataToDigestInputException
    {
        if (null == r)
            throw new NullPointerException();

        try
        {
            XMLSignatureInput refData = r.getContentsAfterTransformation();
            addToDigestInput(refData, r.getDocument());

        } catch (XMLSignatureException ex)
        {
            throw new CannotAddDataToDigestInputException(ex);
        }
    }

    /**
     * Adds a {@code Node} to the input. The node is canonicalized.
     * @param n the node to be added
     * @throws CannotAddDataToDigestInputException if there is an error adding the node
     * @throws NullPointerException if {@code n} is {@code null}
     */
    public void addNode(Node n) throws CannotAddDataToDigestInputException
    {
        if (null == n)
            throw new NullPointerException();

        addToDigestInput(new XMLSignatureInput(n), n.getOwnerDocument());
    }

    private void addToDigestInput(XMLSignatureInput refData, Document doc) throws CannotAddDataToDigestInputException
    {
        try
        {
            if (refData.isNodeSet() || refData.isElement())
            {
                Transform t = Transform.getInstance(doc, canonMethodUri);
                refData = t.performTransform(refData);
                // Fall through to add the bytes resulting from the canonicalization.
            }

            if (refData.isByteArray())
                digestInput.write(refData.getBytes());
            else if (refData.isOctetStream())
                StreamUtils.readWrite(refData.getOctetStream(), digestInput);
        } catch (Exception ex)
        {
            throw new CannotAddDataToDigestInputException(ex);
        }
    }

    /**
     * Gets the octet-stream corresponding to the actual state of the input.
     * @return the octet-stream (always a new instance)
     */
    public byte[] getBytes()
    {
        return digestInput.toByteArray();
    }
}


