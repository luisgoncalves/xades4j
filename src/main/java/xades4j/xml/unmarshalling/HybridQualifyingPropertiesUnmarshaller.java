/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 * Copyright (C) 2012 Hubert Kario - QBS.
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

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import xades4j.properties.ArchiveTimeStampProperty;
import xades4j.properties.AttrAuthoritiesCertValuesProperty;
import xades4j.properties.AttributeRevocationValuesProperty;
import xades4j.properties.CertificateValuesProperty;
import xades4j.properties.CompleteCertificateRefsProperty;
import xades4j.properties.CompleteRevocationRefsProperty;
import xades4j.properties.CounterSignatureProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.RevocationValuesProperty;
import xades4j.properties.SigAndRefsTimeStampProperty;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.properties.TimeStampValidationDataProperty;
import xades4j.properties.UnsignedSignatureProperty;
import xades4j.xml.bind.xades.XmlCertificateValuesType;
import xades4j.xml.bind.xades.XmlCompleteCertificateRefsType;
import xades4j.xml.bind.xades.XmlCompleteRevocationRefsType;
import xades4j.xml.bind.xades.XmlCounterSignatureType;
import xades4j.xml.bind.xades.XmlQualifyingPropertiesType;
import xades4j.xml.bind.xades.XmlRevocationValuesType;
import xades4j.xml.bind.xades.XmlValidationDataType;
import xades4j.xml.bind.xades.XmlXAdESTimeStampType;

public final class HybridQualifyingPropertiesUnmarshaller implements
        QualifyingPropertiesUnmarshaller
{
    private static final JAXBContext jaxbContext;
    private final UnmarshallerModule<?>[] modules;
    private boolean acceptUnknown = false;

    static
    {
        try
        {
            jaxbContext = JAXBContext.newInstance(XmlQualifyingPropertiesType.class);
        }
        catch(JAXBException e)
        {
            throw new UnsupportedOperationException(e);
        }
    }

    public HybridQualifyingPropertiesUnmarshaller()
    {
        this.modules = new UnmarshallerModule[3];
        this.modules[0] = new SignedSigPropsModule();
        this.modules[1] = new SignedDataObjPropsModule();
        this.modules[2] = new UnsignedDataObjPropsModule();
    }

    @Override
    public void setAcceptUnknownProperties(boolean accept)
    {
        for (UnmarshallerModule<?> module : modules)
        {
            module.setAcceptUnknownProperties(accept);
        }
        acceptUnknown = accept;
    }

    @Override
    public void unmarshalProperties(Element qualifyingProps,
            QualifyingPropertiesDataCollector propertyDataCollector)
            throws UnmarshalException
    {
        /*
         * Unmarshall SignedSignatureProperties, SignedDataObjectProperties and
         * UnsignedDataObjectProperties.
         */
        XmlQualifyingPropertiesType xmlQualifyingProps = null;
        try
        {
            // Create the JAXB unmarshaller and unmarshalProperties the root JAXB element
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            JAXBElement<XmlQualifyingPropertiesType> qualifPropsElem =
                    (JAXBElement<XmlQualifyingPropertiesType>)unmarshaller.unmarshal(qualifyingProps,
                            XmlQualifyingPropertiesType.class);
            xmlQualifyingProps = qualifPropsElem.getValue();
        } catch (javax.xml.bind.UnmarshalException ex)
        {
            throw new UnmarshalException("Cannot bind XML elements to Java classes", ex);
        } catch (JAXBException ex)
        {
            throw new UnmarshalException("Cannot unmarshall properties. Error on JAXB unmarshalling.", ex);
        }

        // Iterate the modules to convert the different types of properties.
        for (UnmarshallerModule<?> module : modules)
        {
            module.convertProperties(xmlQualifyingProps, qualifyingProps, propertyDataCollector);
        }

        /*
         * Unmarshall UnsignedSignatureProperties
         */
        Element unsignedSignatureProperties = findUnsignedSignaturePropertiesNode(qualifyingProps);
        if (unsignedSignatureProperties == null)
            return;

        // because the order of properties is important
        unmarshalUnsignedSignatureProperties(unsignedSignatureProperties, propertyDataCollector);
    }

    private Element findUnsignedSignaturePropertiesNode(Element qualifyingProps)
            throws UnmarshalException
    {
        // find UnsignedProperties element
        NodeList qualifyingPropsNodes = qualifyingProps.getChildNodes();
        Element unsignedProperties = null;
        for (int i=0; i < qualifyingPropsNodes.getLength(); i++)
        {
            Node item = qualifyingPropsNodes.item(i);
            if (item.getNodeType() != Node.ELEMENT_NODE)
                continue;

            Element elem = (Element) item;
            if (elem.getLocalName().equalsIgnoreCase(QualifyingProperty.UNSIGNED_PROPS_TAG)
                    && elem.getNamespaceURI().equals(QualifyingProperty.XADES_XMLNS))
                if (unsignedProperties == null)
                    unsignedProperties = elem;
                else
                    throw new UnmarshalException("Multiple UnsignedProperties nodes in signature!");
        }
        if (unsignedProperties == null)
            return null; // no unsigned properties, nothing to unmarshall

        // find UnsignedSignatureProperties element
        NodeList unsignedPropsNodes = unsignedProperties.getChildNodes();
        Element unsignedSignatureProperties = null;
        for (int i=0; i < unsignedPropsNodes.getLength(); i++)
        {
            Node item = unsignedPropsNodes.item(i);
            if (item.getNodeType() != Node.ELEMENT_NODE)
                continue;

            Element elem = (Element) item;
            if (elem.getLocalName().equalsIgnoreCase(QualifyingProperty.UNSIGNED_SIGNATURE_PROPS_TAG)
                    && elem.getNamespaceURI().equals(QualifyingProperty.XADES_XMLNS))
                if (unsignedSignatureProperties == null)
                    unsignedSignatureProperties = elem;
                else
                    throw new UnmarshalException("Multiple UnsignedSignatureProperties nodes in signature");
        }
        if (unsignedSignatureProperties == null)
            return null; // no unsigned signature properties, nothing to unmarshall
        return unsignedSignatureProperties;
    }

    private Node getNextElementNode(Node node)
    {
        while (node != null && node.getNodeType() != Node.ELEMENT_NODE)
            node = node.getNextSibling();
        return node;
    }

    private boolean isNodeTheProperty(Node node, Class<? extends UnsignedSignatureProperty> clazz)
    {
        Field propNameField;
        Field namespaceField;
        try {
            propNameField = clazz.getField("PROP_NAME");
            if (!clazz.equals(ArchiveTimeStampProperty.class) &&
                    !clazz.equals(TimeStampValidationDataProperty.class))
                namespaceField = clazz.getField("XADES_XMLNS");
            else
                namespaceField = clazz.getField("XADESV141_XMLNS");
        } catch (Exception e)
        {
            throw new RuntimeException("Wrong class passed to isNodeTheProperty metod", e);
        }
        String propName;
        String namespace;
        try {
            propName = (String) propNameField.get(null);
            namespace = (String) namespaceField.get(null);
        } catch (Exception e)
        {
            throw new RuntimeException("Wrong class passed to isNodeTheProperty metod", e);
        }

        if (node.getLocalName().equalsIgnoreCase(propName) &&
                node.getNamespaceURI().equalsIgnoreCase(namespace))
            return true;

        return false;
    }


    private <T> JAXBElement<T> unmarshallElement(Node node, Class<T> clazz)
            throws UnmarshalException
    {
        JAXBContext jaxbCont = null;
        try
        {
            jaxbCont = JAXBContext.newInstance(clazz);
        } catch (JAXBException e)
        {
            throw new UnmarshalException("JAXB initialization failure", e);
        }
        JAXBElement<T> unmarshalledElement;
        try
        {
            Unmarshaller unmarshaller = jaxbCont.createUnmarshaller();
            unmarshalledElement = unmarshaller.unmarshal(node, clazz);
        } catch (JAXBException e)
        {
            throw new UnmarshalException(
                    "Property " + node.getLocalName() + " unmarshalling error", e);
        }
        return unmarshalledElement;
    }

    private void unmarshalUnsignedSignatureProperties(Element unsignedSigProps,
            QualifyingPropertiesDataCollector propertyDataCollector)
            throws UnmarshalException
    {
        for(Node node = unsignedSigProps.getFirstChild(); node != null; node = node.getNextSibling())
        {
            // go past text (line breaks), CDATA, comments, etc.
            node = getNextElementNode(node);
            if (node == null)
                return;

            if (isNodeTheProperty(node, SignatureTimeStampProperty.class))
            {
                JAXBElement<XmlXAdESTimeStampType> sigTimeStampElem =
                        unmarshallElement(node, XmlXAdESTimeStampType.class);

                List<XmlXAdESTimeStampType> xmlSigTimeStamp = new ArrayList<XmlXAdESTimeStampType>();
                xmlSigTimeStamp.add(sigTimeStampElem.getValue());
                FromXmlSignatureTimeStampConverter sigTSConv = new FromXmlSignatureTimeStampConverter();

                sigTSConv.convertTimeStamps(xmlSigTimeStamp,
                        propertyDataCollector);

            } else if (isNodeTheProperty(node, CompleteCertificateRefsProperty.class))
            {
                JAXBElement<XmlCompleteCertificateRefsType> completeCertRefsElem =
                        unmarshallElement(node, XmlCompleteCertificateRefsType.class);

                FromXmlCompleteCertRefsConverter compCertRefsConverter =
                        new FromXmlCompleteCertRefsConverter();

                compCertRefsConverter.convertFromObject(completeCertRefsElem.getValue(),
                        propertyDataCollector);

            } else if (isNodeTheProperty(node, CompleteRevocationRefsProperty.class))
            {
                JAXBElement<XmlCompleteRevocationRefsType> completeRevocRefsElem =
                        unmarshallElement(node, XmlCompleteRevocationRefsType.class);

                FromXmlCompleteRevocRefsConverter compCertRefsConverter =
                        new FromXmlCompleteRevocRefsConverter();

                compCertRefsConverter.convertFromObject(completeRevocRefsElem.getValue(),
                        propertyDataCollector);

            } else if (isNodeTheProperty(node, SigAndRefsTimeStampProperty.class))
            {
                JAXBElement<XmlXAdESTimeStampType> sigAndRefsTimeStampElem =
                        unmarshallElement(node, XmlXAdESTimeStampType.class);

                List<XmlXAdESTimeStampType> xmlSigAndRefsTimeStamp = new ArrayList<XmlXAdESTimeStampType>();
                xmlSigAndRefsTimeStamp.add(sigAndRefsTimeStampElem.getValue());
                FromXmlSigAndRefsTimeStampConverter sigTSConv =
                        new FromXmlSigAndRefsTimeStampConverter();

                sigTSConv.convertTimeStamps(xmlSigAndRefsTimeStamp,
                        propertyDataCollector);

            } else if (isNodeTheProperty(node, CertificateValuesProperty.class))
            {
                JAXBElement<XmlCertificateValuesType> certificateValuesElem =
                        unmarshallElement(node, XmlCertificateValuesType.class);

                FromXmlCertificateValuesConverter certValuesConverter =
                        new FromXmlCertificateValuesConverter();

                certValuesConverter.convertFromObject(certificateValuesElem.getValue(),
                        propertyDataCollector);

            } else if (isNodeTheProperty(node, RevocationValuesProperty.class))
            {
                JAXBElement<XmlRevocationValuesType> revocationValuesElem =
                        unmarshallElement(node, XmlRevocationValuesType.class);

                FromXmlRevocationValuesConverter revocValuesConverter =
                        new FromXmlRevocationValuesConverter();

                revocValuesConverter.convertFromObject(revocationValuesElem.getValue(),
                        propertyDataCollector);

            } else if (isNodeTheProperty(node, AttrAuthoritiesCertValuesProperty.class))
            {

                JAXBElement<XmlCertificateValuesType> attrAuthCertValElem =
                        unmarshallElement(node, XmlCertificateValuesType.class);

                FromXmlAttrAuthoritiesCertValuesConverter attrAuthCertValConverter =
                        new FromXmlAttrAuthoritiesCertValuesConverter();

                attrAuthCertValConverter.convertFromObject(attrAuthCertValElem.getValue(),
                        propertyDataCollector);
            } else if (isNodeTheProperty(node, AttributeRevocationValuesProperty.class))
            {
                JAXBElement<XmlRevocationValuesType> revocationValuesElem =
                        unmarshallElement(node, XmlRevocationValuesType.class);

                FromXmlAttributeRevocationValuesConverter revocValuesConverter =
                        new FromXmlAttributeRevocationValuesConverter();

                revocValuesConverter.convertFromObject(revocationValuesElem.getValue(),
                        propertyDataCollector);

            } else if (isNodeTheProperty(node, CounterSignatureProperty.class))
            {
                JAXBElement<XmlCounterSignatureType> counterSignatureElem =
                        unmarshallElement(node, XmlCounterSignatureType.class);

                // TODO counter signature not supported
                continue;
            } else if (isNodeTheProperty(node, ArchiveTimeStampProperty.class))
            {
                JAXBElement<XmlXAdESTimeStampType> xmlArchiveTimeStampElem =
                        unmarshallElement(node, XmlXAdESTimeStampType.class);

                List<XmlXAdESTimeStampType> archivalTimeStamps =
                        new ArrayList<XmlXAdESTimeStampType>();
                archivalTimeStamps.add(xmlArchiveTimeStampElem.getValue());

                FromXmlArchiveTimeStampConverter archTSConv =
                        new FromXmlArchiveTimeStampConverter();

                archTSConv.convertTimeStamps(archivalTimeStamps , propertyDataCollector);

            } else if (isNodeTheProperty(node, TimeStampValidationDataProperty.class))
            {
                JAXBElement<XmlValidationDataType> xmlTimeStampValidationDataElem =
                        unmarshallElement(node, XmlValidationDataType.class);

                FromXmlTimeStampValidationDataConverter tsValidationDataConverter =
                        new FromXmlTimeStampValidationDataConverter();

                List<XmlValidationDataType> xmlTimeStampValidationData =
                        new ArrayList<XmlValidationDataType>();
                xmlTimeStampValidationData.add(xmlTimeStampValidationDataElem.getValue());
                tsValidationDataConverter.convertFromObject(xmlTimeStampValidationData ,
                        propertyDataCollector);
            } else if (!acceptUnknown) // not recognized property
                throw new UnmarshalException("Unknown unsigned signature property: "
                        + node.getLocalName());
            else if (acceptUnknown)
                continue;

            propertyDataCollector.linkPropertyToElem((Element)node);

        }
    }
}
