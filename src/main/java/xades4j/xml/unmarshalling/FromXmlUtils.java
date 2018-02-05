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
package xades4j.xml.unmarshalling;

import java.util.HashMap;
import java.util.Map;
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
import xades4j.xml.bind.xmldsig.XmlX509IssuerSerialType;

/**
 *
 * @author Luís
 */
class FromXmlUtils
{
    private FromXmlUtils()
    {
    }

    static void createAndCertificateRefs(
            XmlCertIDListType xmlCertRefs,
            BaseCertRefsData certRefsData)
    {
        for (XmlCertIDType xmlCertIDType : xmlCertRefs.getCert())
        {
            /* All the elements within Cert are marked with 'required' */

            XmlX509IssuerSerialType is = xmlCertIDType.getIssuerSerial();
            XmlDigestAlgAndValueType d = xmlCertIDType.getCertDigest();

            CertRef ref = new CertRef(
                    is.getX509IssuerName(),
                    is.getX509SerialNumber(),
                    d.getDigestMethod().getAlgorithm(),
                    d.getDigestValue()); // Digest value is already decoded.

            certRefsData.addCertRef(ref);
        }
    }

    private static final Map<XmlQualifierType, IdentifierType> identifierTypeConv;

    static
    {
        identifierTypeConv = new HashMap<XmlQualifierType, IdentifierType>(3);
        identifierTypeConv.put(null, IdentifierType.URI);
        identifierTypeConv.put(XmlQualifierType.OID_AS_URI, IdentifierType.OIDAsURI);
        identifierTypeConv.put(XmlQualifierType.OID_AS_URN, IdentifierType.OIDAsURN);
    }

    static ObjectIdentifier getObjectIdentifier(XmlObjectIdentifierType xmlObjId)
    {
        if (null == xmlObjId)
            return null;
        XmlIdentifierType xmlId = xmlObjId.getIdentifier();
        return new ObjectIdentifier(
                xmlId.getValue(),
                identifierTypeConv.get(xmlId.getQualifier()),
                xmlObjId.getDescription());
    }
}
