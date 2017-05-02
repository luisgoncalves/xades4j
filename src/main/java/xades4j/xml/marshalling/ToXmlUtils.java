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

import java.util.EnumMap;
import java.util.List;
import xades4j.properties.IdentifierType;
import xades4j.properties.ObjectIdentifier;
import xades4j.properties.data.BaseCertRefsData;
import xades4j.properties.data.CertRef;
import xades4j.xml.bind.xades.XmlCertIDListType;
import xades4j.xml.bind.xades.XmlCertIDType;
import xades4j.xml.bind.xades.XmlDigestAlgAndValueType;
import xades4j.xml.bind.xades.XmlIdentifierType;
import xades4j.xml.bind.xades.XmlObjectIdentifierType;
import xades4j.xml.bind.xades.XmlQualifierType;
import xades4j.xml.bind.xmldsig.XmlDigestMethodType;
import xades4j.xml.bind.xmldsig.XmlX509IssuerSerialType;

/**
 * @author Luís
 */
class ToXmlUtils
{
    ToXmlUtils()
    {
    }
    private static final EnumMap<IdentifierType, XmlQualifierType> identifierTypeConv;

    static
    {
        identifierTypeConv = new EnumMap(IdentifierType.class);
        identifierTypeConv.put(IdentifierType.OIDAsURI, XmlQualifierType.OID_AS_URI);
        identifierTypeConv.put(IdentifierType.OIDAsURN, XmlQualifierType.OID_AS_URN);
    }

    static XmlObjectIdentifierType getXmlObjectId(ObjectIdentifier objId)
    {
        XmlObjectIdentifierType xmlObjId = new XmlObjectIdentifierType();

        // Object identifier
        XmlIdentifierType xmlId = new XmlIdentifierType();
        xmlId.setValue(objId.getIdentifier());
        // If it is IdentifierType.URI the converter returns null, which is the
        // same as not specifying a qualifier.
        xmlId.setQualifier(identifierTypeConv.get(objId.getIdentifierType()));
        xmlObjId.setIdentifier(xmlId);
        
        // Description
        xmlObjId.setDescription(objId.getDescription());

        return xmlObjId;
    }

    /**/
    static XmlCertIDListType getXmlCertRefList(BaseCertRefsData certRefsData)
    {
        XmlCertIDListType xmlCertRefListProp = new XmlCertIDListType();
        List<XmlCertIDType> xmlCertRefList = xmlCertRefListProp.getCert();

        XmlDigestAlgAndValueType certDigest;
        XmlDigestMethodType certDigestMethod;
        XmlX509IssuerSerialType issuerSerial;
        XmlCertIDType certID;

        for (CertRef certRef : certRefsData.getCertRefs())
        {
            certDigestMethod = new XmlDigestMethodType();
            certDigestMethod.setAlgorithm(certRef.digestAlgUri);
            certDigest = new XmlDigestAlgAndValueType();
            certDigest.setDigestMethod(certDigestMethod);
            certDigest.setDigestValue(certRef.digestValue);

            issuerSerial = new XmlX509IssuerSerialType();
            issuerSerial.setX509IssuerName(certRef.issuerDN);
            issuerSerial.setX509SerialNumber(certRef.serialNumber);

            certID = new XmlCertIDType();
            certID.setCertDigest(certDigest);
            certID.setIssuerSerial(issuerSerial);
            xmlCertRefList.add(certID);
        }

        return xmlCertRefListProp;
    }
}
