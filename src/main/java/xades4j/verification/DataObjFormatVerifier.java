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

import java.util.Collection;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.Reference;
import xades4j.properties.DataObjectFormatProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.DataObjectFormatData;
import xades4j.utils.StringUtils;

/**
 * XAdES section G.2.2.8
 * @author Luís
 */
class DataObjFormatVerifier implements QualifyingPropertyVerifier<DataObjectFormatData>
{
    @Override
    public QualifyingProperty verify(
            DataObjectFormatData propData,
            QualifyingPropertyVerificationContext ctx) throws DataObjectFormatVerificationException
    {
        QualifyingPropertyVerificationContext.SignedObjectsData signedObjsData = ctx.getSignedObjectsData();
        String encoding = propData.getEncoding(), mimeType = propData.getMimeType();

        // XAdES G.2.2.8: "The verifier should check that the ObjectReference element
        // actually references one ds:Reference element from the signature."
        RawDataObjectDesc signedObj = signedObjsData.findSignedDataObject(propData.getObjectRef());
        if (null == signedObj)
            throw new DataObjectFormatReferenceException(propData.getObjectRef());

        // "In addition, should this property refer to a ds:Reference that in turn
        // refers to a ds:Object, the verifier should check the values of attributes
        // MimeType and Encoding (...)."
        Reference signedObjRef = signedObj.getReference();
        if (Reference.OBJECT_URI.equals(signedObjRef.getType()))
        {
            // Get the referenced Object.
            ObjectContainer signedObjObj = signedObjsData.findXMLObject(signedObjRef.getURI());
            if (null == signedObjObj)
                throw new DataObjectFormatReferenceException(signedObjRef.getURI());

            String objEncoding = signedObjObj.getEncoding(),
                    objMimeType = signedObjObj.getMimeType();
            // Compare 'encoding' and 'mimeType', if present on both.
            if (StringUtils.differentStringsIfNotNullNorEmpty(objEncoding, encoding) ||
                    StringUtils.differentStringsIfNotNullNorEmpty(objMimeType, mimeType))
                throw new DataObjectFormatMismatchException(mimeType, encoding, signedObjRef, signedObjObj);
        }

        // Create the property.
        DataObjectFormatProperty formatProp = new DataObjectFormatProperty(mimeType, encoding);
        formatProp.withDescription(propData.getDescription());

        Collection<String> docsUris = propData.getDocumentationUris();
        if (docsUris != null)
            formatProp.withDocumentationUris(docsUris);

        formatProp.withIdentifier(propData.getIdentifier());

        // Associate the property to the data object.
        signedObj.withDataObjectFormat(formatProp);
        return formatProp;
    }
}
