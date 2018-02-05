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

import java.util.List;
import javax.xml.bind.JAXBElement;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.SignaturePolicyBase;
import xades4j.properties.data.SignaturePolicyData;
import xades4j.xml.bind.xades.XmlAnyType;
import xades4j.xml.bind.xades.XmlSigPolicyQualifiersListType;
import xades4j.xml.bind.xades.XmlSignaturePolicyIdType;
import xades4j.xml.bind.xades.XmlSignaturePolicyIdentifierType;
import xades4j.xml.bind.xades.XmlSignedSignaturePropertiesType;

/**
 *
 * @author Luís
 */
class FromXmlSignaturePolicyConverter implements SignedSigPropFromXmlConv
{
    @Override
    public void convertFromObjectTree(
            XmlSignedSignaturePropertiesType xmlProps,
            QualifyingPropertiesDataCollector propertyDataCollector) throws PropertyUnmarshalException
    {
        XmlSignaturePolicyIdentifierType xmlSigPolicy = xmlProps.getSignaturePolicyIdentifier();

        if (null == xmlSigPolicy)
            return;

        if (xmlSigPolicy.getSignaturePolicyImplied() != null)
        {
            propertyDataCollector.setSignaturePolicy(new SignaturePolicyData());
            return;
        }

        XmlSignaturePolicyIdType xmlPolicyId = xmlSigPolicy.getSignaturePolicyId();

        if (xmlPolicyId.getTransforms() != null)
            throw new PropertyUnmarshalException("Signature policy transforms are not supported", SignaturePolicyBase.PROP_NAME);

        propertyDataCollector.setSignaturePolicy(new SignaturePolicyData(
                FromXmlUtils.getObjectIdentifier(xmlPolicyId.getSigPolicyId()),
                xmlPolicyId.getSigPolicyHash().getDigestMethod().getAlgorithm(),
                xmlPolicyId.getSigPolicyHash().getDigestValue(),
                getLocationUrl(xmlPolicyId)));
    }

    private static String getLocationUrl(XmlSignaturePolicyIdType xmlPolicyId) throws PropertyUnmarshalException
    {
        XmlSigPolicyQualifiersListType sigPolicyQualifiers = xmlPolicyId.getSigPolicyQualifiers();
        if(null == sigPolicyQualifiers)
        {
            return null;
        }
        
        List<XmlAnyType> xmlQualifiers = sigPolicyQualifiers.getSigPolicyQualifier();
        for (XmlAnyType xmlQualifier : xmlQualifiers)
        {
            List content = xmlQualifier.getContent();
            if (content.size() == 1 && content.get(0) instanceof JAXBElement)
            {
                JAXBElement xmlSPURI = (JAXBElement)content.get(0);
                if (xmlSPURI.getName().getLocalPart().equals("SPURI") && xmlSPURI.getName().getNamespaceURI().equals(QualifyingProperty.XADES_XMLNS))
                {
                    return (String)xmlSPURI.getValue();
                }
            }
        }
        
        return null;
    }
}
