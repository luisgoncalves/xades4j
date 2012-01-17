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

import org.w3c.dom.Document;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.SignaturePolicyData;
import xades4j.xml.bind.xades.XmlDigestAlgAndValueType;
import xades4j.xml.bind.xades.XmlSignaturePolicyIdType;
import xades4j.xml.bind.xades.XmlSignaturePolicyIdentifierType;
import xades4j.xml.bind.xades.XmlSignedPropertiesType;
import xades4j.xml.bind.xmldsig.XmlDigestMethodType;

/**
 *
 * @author Luís
 */
class ToXmlSignaturePolicyConverter implements SignedPropertyDataToXmlConverter
{
    @Override
    public void convertIntoObjectTree(
            PropertyDataObject propData,
            XmlSignedPropertiesType xmlProps,
            Document doc)
    {
        SignaturePolicyData sigPolicyData = (SignaturePolicyData)propData;
        XmlSignaturePolicyIdentifierType xmlSigPolicy = new XmlSignaturePolicyIdentifierType();

        if (null == sigPolicyData.getIdentifier())
            xmlSigPolicy.setSignaturePolicyImplied();
        else
        {
            XmlSignaturePolicyIdType xmlSigPolicyId = new XmlSignaturePolicyIdType();
            xmlSigPolicyId.setSigPolicyId(ToXmlUtils.getXmlObjectId(sigPolicyData.getIdentifier()));
            xmlSigPolicyId.setSigPolicyHash(getDigest(sigPolicyData));

            xmlSigPolicy.setSignaturePolicyId(xmlSigPolicyId);
        }
        xmlProps.getSignedSignatureProperties().setSignaturePolicyIdentifier(xmlSigPolicy);
    }

    private XmlDigestAlgAndValueType getDigest(SignaturePolicyData sigPolicyData)
    {
        XmlDigestMethodType xmlDigestMethod = new XmlDigestMethodType();
        xmlDigestMethod.setAlgorithm(sigPolicyData.getDigestAlgorithm());

        XmlDigestAlgAndValueType xmlDigest = new XmlDigestAlgAndValueType();
        xmlDigest.setDigestMethod(xmlDigestMethod);
        xmlDigest.setDigestValue(sigPolicyData.getDigestValue());

        return xmlDigest;
    }
}
