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

import com.google.inject.Inject;
import xades4j.properties.data.SigAndDataObjsPropertiesData;
import org.w3c.dom.Node;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.AllDataObjsTimeStampData;
import xades4j.properties.data.CommitmentTypeData;
import xades4j.properties.data.DataObjectFormatData;
import xades4j.properties.data.IndividualDataObjsTimeStampData;
import xades4j.properties.data.SignaturePolicyData;
import xades4j.properties.data.SignatureProdPlaceData;
import xades4j.properties.data.SignerRoleData;
import xades4j.properties.data.SigningCertificateData;
import xades4j.properties.data.SigningTimeData;
import xades4j.xml.bind.xades.ObjectFactory;
import xades4j.xml.bind.xades.XmlSignedDataObjectPropertiesType;
import xades4j.xml.bind.xades.XmlSignedPropertiesType;
import xades4j.xml.bind.xades.XmlSignedSignaturePropertiesType;
import xades4j.xml.marshalling.algorithms.AlgorithmsParametersMarshallingProvider;

/**
 * Default implementation of {@link SignedPropertiesMarshaller}. Based on JAXB.
 * <p>
 * Supports all the signed properties data objects in the library (XAdES 1.4.1)
 * plus the {@code GenericDOMData}.
 * @author Luís
 */
final class DefaultSignedPropertiesMarshaller
        extends BaseJAXBMarshaller<XmlSignedPropertiesType>
        implements SignedPropertiesMarshaller
{
    @Inject
    DefaultSignedPropertiesMarshaller(AlgorithmsParametersMarshallingProvider algorithmsParametersMarshallingProvider)
    {
        super(9, QualifyingProperty.SIGNED_PROPS_TAG);
        
        // Signed signature properties
        super.putConverter(
                SigningCertificateData.class,
                new ToXmlSigningCertificateConverter());
        super.putConverter(
                SigningTimeData.class,
                new ToXmlSigningTimeConverter());
        super.putConverter(SignerRoleData.class,
                new ToXmlSignerRoleConverter());
        super.putConverter(
                SignatureProdPlaceData.class,
                new ToXmlSignatureProductionPlaceConverter());
        super.putConverter(
                SignaturePolicyData.class,
                new ToXmlSignaturePolicyConverter());

        // Signed data objects properties
        super.putConverter(
                DataObjectFormatData.class,
                new ToXmlDataObjectFormatConverter());
        super.putConverter(
                CommitmentTypeData.class,
                new ToXmlCommitmentTypeConverter());
        super.putConverter(
                IndividualDataObjsTimeStampData.class,
                new ToXmlIndivDataObjsTimeStampConverter(algorithmsParametersMarshallingProvider));
        super.putConverter(
                AllDataObjsTimeStampData.class,
                new ToXmlAllDataObjsTimeStampConverter(algorithmsParametersMarshallingProvider));
    }

    /* Methods from SignedPropertiesMarshaller */

    @Override
    public void marshal(SigAndDataObjsPropertiesData signedProps, Node qualifyingPropsNode) throws MarshalException
    {
        XmlSignedPropertiesType xmlSignedProps = new XmlSignedPropertiesType();
        doMarshal(signedProps, qualifyingPropsNode, xmlSignedProps);
    }

    /* Methods from BaseJAXBMarshaller */
    
    @Override
    protected void prepareSigProps(XmlSignedPropertiesType xmlProps)
    {
        // Create SignedSignatureProperties and add it to SignedProperties
        XmlSignedSignaturePropertiesType xmlSignedSigProps = new XmlSignedSignaturePropertiesType();
        xmlProps.setSignedSignatureProperties(xmlSignedSigProps);
    }

    @Override
    protected void prepareDataObjsProps(XmlSignedPropertiesType xmlProps)
    {
        // Create SignedDataObjectProperties and add it to SignedProperties
        XmlSignedDataObjectPropertiesType xmlSignedDataObjProps = new XmlSignedDataObjectPropertiesType();
        xmlProps.setSignedDataObjectProperties(xmlSignedDataObjProps);
    }

    @Override
    protected Object createPropsXmlElem(
            ObjectFactory objFact,
            XmlSignedPropertiesType xmlProps)
    {
        return objFact.createSignedProperties(xmlProps);
    }
}