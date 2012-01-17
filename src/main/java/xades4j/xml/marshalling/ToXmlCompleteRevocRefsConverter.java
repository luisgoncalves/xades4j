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
package xades4j.xml.marshalling;

import java.util.List;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import org.w3c.dom.Document;
import xades4j.properties.data.CRLRef;
import xades4j.properties.data.CompleteRevocationRefsData;
import xades4j.properties.data.PropertyDataObject;
import xades4j.xml.bind.xades.XmlCRLIdentifierType;
import xades4j.xml.bind.xades.XmlCRLRefType;
import xades4j.xml.bind.xades.XmlCRLRefsType;
import xades4j.xml.bind.xades.XmlCompleteRevocationRefsType;
import xades4j.xml.bind.xades.XmlDigestAlgAndValueType;
import xades4j.xml.bind.xades.XmlUnsignedPropertiesType;
import xades4j.xml.bind.xmldsig.XmlDigestMethodType;

/**
 *
 * @author Luís
 */
class ToXmlCompleteRevocRefsConverter implements UnsignedPropertyDataToXmlConverter
{
    @Override
    public void convertIntoObjectTree(
            PropertyDataObject propData,
            XmlUnsignedPropertiesType xmlProps,
            Document doc)
    {
        CompleteRevocationRefsData complRevocRefsData = (CompleteRevocationRefsData)propData;

        // Only CRL refs are supported.
        XmlCRLRefsType xmlCRLRefs = new XmlCRLRefsType();
        List<XmlCRLRefType> xmlCRLRefsList = xmlCRLRefs.getCRLRef();
        try
        {
            for (CRLRef crlRef : complRevocRefsData.getCrlRefs())
            {
                XmlCRLIdentifierType xmlCrlId = new XmlCRLIdentifierType();
                xmlCrlId.setIssueTime(DatatypeFactory.newInstance().newXMLGregorianCalendar(crlRef.issueTime));
                xmlCrlId.setIssuer(crlRef.issuerDN);
                xmlCrlId.setNumber(crlRef.serialNumber); // May be null.

                XmlDigestAlgAndValueType xmlDigest = new XmlDigestAlgAndValueType();
                XmlDigestMethodType xmlDigestMethod = new XmlDigestMethodType();
                xmlDigestMethod.setAlgorithm(crlRef.digestAlgUri);
                xmlDigest.setDigestValue(crlRef.digestValue);
                xmlDigest.setDigestMethod(xmlDigestMethod);

                XmlCRLRefType xmlCrlRef = new XmlCRLRefType();
                xmlCrlRef.setCRLIdentifier(xmlCrlId);
                xmlCrlRef.setDigestAlgAndValue(xmlDigest);

                xmlCRLRefsList.add(xmlCrlRef);
            }
        } catch (DatatypeConfigurationException ex)
        {
            throw new UnsupportedOperationException(ex.getMessage(), ex);
        }

        XmlCompleteRevocationRefsType xmlComplRevocRefs = new XmlCompleteRevocationRefsType();
        // Only CRL refs are supported.
        xmlComplRevocRefs.setCRLRefs(xmlCRLRefs);
        xmlProps.getUnsignedSignatureProperties().setCompleteRevocationRefs(xmlComplRevocRefs);
    }
}
