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
package xades4j.xml.marshalling;

import java.util.List;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
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
            XmlUnsignedPropertiesType xmlProps)
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
