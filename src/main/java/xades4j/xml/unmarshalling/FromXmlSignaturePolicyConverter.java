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

import xades4j.properties.ObjectIdentifier;
import xades4j.properties.SignaturePolicyBase;
import xades4j.properties.data.SignaturePolicyData;
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

        ObjectIdentifier policyId = FromXmlUtils.getObjectIdentifier(xmlPolicyId.getSigPolicyId());
        propertyDataCollector.setSignaturePolicy(new SignaturePolicyData(
                policyId,
                xmlPolicyId.getSigPolicyHash().getDigestMethod().getAlgorithm(),
                xmlPolicyId.getSigPolicyHash().getDigestValue()));
    }
}
