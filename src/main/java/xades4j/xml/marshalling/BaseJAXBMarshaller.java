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

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.GenericDOMData;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.SigAndDataObjsPropertiesData;
import xades4j.xml.bind.xades.ObjectFactory;
import xades4j.utils.CollectionUtils;
import xades4j.utils.DOMHelper;

/**
 *
 * @author Luís
 */
abstract class BaseJAXBMarshaller<TXml>
{
    private final Map<Class, QualifyingPropertyDataToXmlConverter<TXml>> converters;
    private final String propsElemName;

    protected BaseJAXBMarshaller(int convertersInitialSize, String propsElemName)
    {
        this.converters = new HashMap<Class, QualifyingPropertyDataToXmlConverter<TXml>>(convertersInitialSize);
        this.propsElemName = propsElemName;
    }

    protected void putConverter(
            Class<? extends PropertyDataObject> propClass,
            QualifyingPropertyDataToXmlConverter<TXml> propConverter)
    {
        this.converters.put(propClass, propConverter);
    }

    protected void doMarshal(
            SigAndDataObjsPropertiesData properties,
            Node qualifyingPropsNode,
            TXml xmlProps) throws MarshalException
    {
        if (properties.isEmpty())
            return;

        Document doc = qualifyingPropsNode.getOwnerDocument();

        Collection<PropertyDataObject> unknownSigProps = null;
        if (!properties.getSigProps().isEmpty())
        {
            prepareSigProps(xmlProps);
            unknownSigProps = convert(properties.getSigProps(), xmlProps, doc);
        }

        Collection<PropertyDataObject> unknownDataObjProps = null;
        if (!properties.getDataObjProps().isEmpty())
        {
            prepareDataObjsProps(xmlProps);
            unknownDataObjProps = convert(properties.getDataObjProps(), xmlProps, doc);
        }

        if (propsNotAlreadyPresent(qualifyingPropsNode))
            // If the QualifyingProperties node doesn't already have an element
            // for the current type of properties, do a JAXB marshalling into it.
            doJAXBMarshalling(qualifyingPropsNode, xmlProps);
        else
        {
            // If it has, marshall into a temp node and transfer the resulting
            // nodes into the appropriate QualifyingProperties children.
            Node tempNode = DOMHelper.createElement(
                    qualifyingPropsNode.getOwnerDocument(), "temp", null, QualifyingProperty.XADES_XMLNS);
            // - A little work around to inherit the namespace node defined in
            //   the document. Its just a matter of style.
            qualifyingPropsNode.appendChild(tempNode);
            doJAXBMarshalling(tempNode, xmlProps);
            qualifyingPropsNode.removeChild(tempNode);
            transferProperties(qualifyingPropsNode, tempNode);
        }

        // The top-most XML element for the current type of properties.
        Element topMostPropsElem = DOMHelper.getFirstDescendant(
                (Element)qualifyingPropsNode,
                QualifyingProperty.XADES_XMLNS, propsElemName);

        if (!CollectionUtils.nullOrEmpty(unknownSigProps))
            marshallUnknownProps(unknownSigProps, DOMHelper.getFirstChildElement(topMostPropsElem));
        if (!CollectionUtils.nullOrEmpty(unknownDataObjProps))
            marshallUnknownProps(unknownDataObjProps, DOMHelper.getLastChildElement(topMostPropsElem));
    }

    private Collection<PropertyDataObject> convert(
            Collection<PropertyDataObject> props,
            TXml xmlProps,
            Document doc) throws MarshalException
    {
        Collection<PropertyDataObject> unknownProps = null;

        // Convert each property to the corresponding JAXB object. Each converter
        // will add the corresponding object to the tree.
        // If a converter is not found, it means that the property is unknown in
        // this version of XAdES; it will be converted afterwards.
        QualifyingPropertyDataToXmlConverter<TXml> conv;
        for (PropertyDataObject p : props)
        {
            conv = this.converters.get(p.getClass());
            if (null == conv)
            {
                unknownProps = CollectionUtils.newIfNull(unknownProps, 1);
                unknownProps.add(p);
            } else
                conv.convertIntoObjectTree(p, xmlProps, doc);
        }
        return unknownProps;
    }

    private boolean propsNotAlreadyPresent(Node qualifyingPropsNode)
    {
        return null == DOMHelper.getFirstDescendant(
                (Element)qualifyingPropsNode,
                QualifyingProperty.XADES_XMLNS, propsElemName);
    }

    private void doJAXBMarshalling(Node qualifyingPropsNode, TXml xmlProps) throws MarshalException
    {
        try
        {
            // Create the JAXB marshaller.
            JAXBContext jaxbContext = JAXBContext.newInstance(xmlProps.getClass());
            Marshaller marshaller = jaxbContext.createMarshaller();
            // Create the root JAXBElement.
            Object propsElem = createPropsXmlElem(new ObjectFactory(), xmlProps);
            // Marshal the properties.
            marshaller.marshal(propsElem, qualifyingPropsNode);
        } catch (JAXBException ex)
        {
            throw new MarshalException("Error on JAXB marshalling", ex);
        }
    }

    private void transferProperties(Node qualifPropsNode, Node tempNode)
    {
        // The QualifyingProperties node already has a child element for the current
        // type of properties.
        Element existingProps = DOMHelper.getFirstDescendant(
                (Element)qualifPropsNode,
                QualifyingProperty.XADES_XMLNS, propsElemName);
        // The new properties (Signed or Unsigned) were marshalled into the temp
        // node.
        Element newProps = DOMHelper.getFirstChildElement(tempNode);

        Element newSpecificProps = DOMHelper.getFirstChildElement(newProps);
        do
        {
            Element existingSpecificProps = DOMHelper.getFirstDescendant(
                    existingProps, newSpecificProps.getNamespaceURI(), newSpecificProps.getLocalName());

            if (null == existingSpecificProps)
                // No element for these properties. Append the new element to the existing
                // properties.
                existingProps.appendChild(newSpecificProps);
            else
                // There are properties. Transfer all the new properties into the existing
                // element.
                transferChildren(newSpecificProps, existingSpecificProps);

            newSpecificProps = DOMHelper.getNextSiblingElement(newSpecificProps);

        } while (newSpecificProps != null);


    }

    private void transferChildren(Element from, Element to)
    {
        Node child = from.getFirstChild();
        Node childSib;
        while (child != null)
        {
            // Need this temp node because when the 'child' node is appended to
            // the destination subtree I won't be able to access the siblings on
            // the previous subtree.
            childSib = child.getNextSibling();
            to.appendChild(child);
            child = childSib;
        }
    }

    private void marshallUnknownProps(
            Collection<PropertyDataObject> unknownProps,
            Element parent) throws MarshalException
    {
        for (PropertyDataObject pData : unknownProps)
        {
            if (!(pData instanceof GenericDOMData))
                throw new UnsupportedDataObjectException(pData);
            Node propElem = ((GenericDOMData)pData).getPropertyElement();
            if (propElem.getOwnerDocument() != parent.getOwnerDocument())
                propElem = parent.getOwnerDocument().importNode(propElem, true);
            parent.appendChild(propElem);
        }
    }

    protected abstract void prepareSigProps(TXml xmlProps);

    protected abstract void prepareDataObjsProps(TXml xmlProps);

    protected abstract Object createPropsXmlElem(
            ObjectFactory objFact,
            TXml xmlProps);
}
