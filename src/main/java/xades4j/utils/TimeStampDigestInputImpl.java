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
package xades4j.utils;

import java.io.ByteArrayOutputStream;
import java.util.List;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transform;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import xades4j.algorithms.Algorithm;
import xades4j.xml.marshalling.algorithms.AlgorithmsParametersMarshallingProvider;

/**
 *
 * @author Luís
 */
class TimeStampDigestInputImpl implements TimeStampDigestInput
{
    private final Algorithm c14n;
    private final AlgorithmsParametersMarshallingProvider parametersMarshallingProvider;

    private final ByteArrayOutputStream digestInput;

    TimeStampDigestInputImpl(Algorithm c14n, AlgorithmsParametersMarshallingProvider parametersMarshallingProvider)
    {
        // It would be better to have a Canonicalizer passed on the constructor
        // but it doesn't have a method that receives a XMlSignatureInput. Apache's
        // C14N transforms have some bug circumvent checks when mapping XMLSignatureInput
        // to the Canonicalizer methods, so it's better to keep using C14N via Transform.

        this.c14n = c14n;
        this.parametersMarshallingProvider = parametersMarshallingProvider;
        this.digestInput = new ByteArrayOutputStream();
    }

    @Override
    public void addReference(Reference r) throws CannotAddDataToDigestInputException
    {
        if (null == r)
        {
            throw new NullPointerException();
        }

        try
        {
            XMLSignatureInput refData = r.getContentsAfterTransformation();
            addToDigestInput(refData, r.getDocument());

        } catch (XMLSignatureException ex)
        {
            throw new CannotAddDataToDigestInputException(ex);
        }
    }

    @Override
    public void addNode(Node n) throws CannotAddDataToDigestInputException
    {
        if (null == n)
        {
            throw new NullPointerException();
        }

        addToDigestInput(new XMLSignatureInput(n), n.getOwnerDocument());
    }

    private void addToDigestInput(XMLSignatureInput refData, Document doc) throws CannotAddDataToDigestInputException
    {
        try
        {
            if (refData.isNodeSet() || refData.isElement())
            {
                Transform c14nTransform = TransformUtils.createTransform(this.c14n, this.parametersMarshallingProvider, doc);
                refData = c14nTransform.performTransform(refData);
                // Fall through to add the bytes resulting from the canonicalization.
            }

            if (refData.isByteArray())
            {
                digestInput.write(refData.getBytes());
            } else if (refData.isOctetStream())
            {
                StreamUtils.readWrite(refData.getOctetStream(), digestInput);
            }
        }
        catch (Exception ex)
        {
            throw new CannotAddDataToDigestInputException(ex);
        }
    }

    @Override
    public byte[] getBytes()
    {
        return digestInput.toByteArray();
    }
}
