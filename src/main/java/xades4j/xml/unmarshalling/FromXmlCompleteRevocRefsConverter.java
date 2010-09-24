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
package xades4j.xml.unmarshalling;

import xades4j.properties.CompleteRevocationRefsProperty;
import xades4j.properties.data.CRLRef;
import xades4j.properties.data.CompleteRevocationRefsData;
import xades4j.xml.bind.xades.XmlCRLIdentifierType;
import xades4j.xml.bind.xades.XmlCRLRefType;
import xades4j.xml.bind.xades.XmlCRLRefsType;
import xades4j.xml.bind.xades.XmlCompleteRevocationRefsType;
import xades4j.xml.bind.xades.XmlUnsignedSignaturePropertiesType;

/**
 *
 * @author Luís
 */
class FromXmlCompleteRevocRefsConverter implements UnsignedSigPropFromXmlConv
{
    @Override
    public void convertFromObjectTree(
            XmlUnsignedSignaturePropertiesType xmlProps,
            QualifyingPropertiesDataCollector propertyDataCollector) throws PropertyUnmarshalException
    {
        XmlCompleteRevocationRefsType xmlCompleteRevocRefs = xmlProps.getCompleteRevocationRefs();
        if (null == xmlCompleteRevocRefs)
            return;

        if (xmlCompleteRevocRefs.getOCSPRefs() != null || xmlCompleteRevocRefs.getOtherRefs() != null)
            throw new PropertyUnmarshalException("Only CRL references are supported", CompleteRevocationRefsProperty.PROP_NAME);

        XmlCRLRefsType xmlCRLRefs = xmlCompleteRevocRefs.getCRLRefs();
        if (null == xmlCRLRefs)
            throw new PropertyUnmarshalException("CRL references not present", CompleteRevocationRefsProperty.PROP_NAME);

        CompleteRevocationRefsData complRevocRefsData = new CompleteRevocationRefsData();

        for (XmlCRLRefType xmlCRLRef : xmlCRLRefs.getCRLRef())
        {
            XmlCRLIdentifierType xmlCrlId = xmlCRLRef.getCRLIdentifier();
            complRevocRefsData.addCRLRef(new CRLRef(
                    xmlCrlId.getIssuer(),
                    xmlCrlId.getNumber(),
                    xmlCRLRef.getDigestAlgAndValue().getDigestMethod().getAlgorithm(),
                    xmlCRLRef.getDigestAlgAndValue().getDigestValue(),
                    xmlCrlId.getIssueTime().toGregorianCalendar()));
        }

        propertyDataCollector.setCompleteRevocRefs(complRevocRefsData);
    }
}
