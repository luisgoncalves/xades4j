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
package xades4j.verification;

import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.Reference;

/**
 * Thrown during validation of the {@code DataObjectFormat} property if the corresponding
 * {@code Reference} references an {@code Object} and mime-type and/or encoding
 * in the property an in the {@code Object} are not equal.
 * @author Luís
 */
public class DataObjectFormatMismatchException extends DataObjectFormatVerificationException
{
    private final String mimeType;
    private final String encoding;
    private final ObjectContainer object;
    private final Reference reference;

    public DataObjectFormatMismatchException(
            String mimeType, String encoding,
            Reference ref, ObjectContainer obj)
    {
        this.mimeType = mimeType;
        this.encoding = encoding;
        this.reference = ref;
        this.object = obj;
    }

    public String getMimeType()
    {
        return mimeType;
    }

    public String getEncoding()
    {
        return encoding;
    }

    public ObjectContainer getObject()
    {
        return object;
    }

    public Reference getReference()
    {
        return reference;
    }

    @Override
    protected String getVerificationMessage()
    {
        StringBuilder b = new StringBuilder("Format mismatch between property and XMLObject: ");
        if (!mimeType.equals(object.getMimeType()))
            b.append(String.format("expected mime-type '%s', found '%s';", mimeType, object.getMimeType()));
        if (!encoding.equals(object.getEncoding()))
            b.append(String.format("expected encoding '%s', found '%s';", encoding, object.getEncoding()));
        return b.toString();
    }
}
