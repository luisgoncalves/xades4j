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

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import org.w3c.dom.Element;
import xades4j.xml.bind.xades.XmlQualifyingPropertiesType;

/**
 * Default implementation of {@link QualifyingPropertiesUnmarshaller}. Based on JAXB.
 * <p>
 * Supports all the unsigned properties data objects up to XAdES-C, except {@code SignerRole}
 * and attributes validation data properties.
 * @author Luís
 */
final class DefaultQualifyingPropertiesUnmarshaller
        implements QualifyingPropertiesUnmarshaller
{
    private final UnmarshallerModule[] modules;

    public DefaultQualifyingPropertiesUnmarshaller()
    {
        this.modules = new UnmarshallerModule[4];
        this.modules[0] = new SignedSigPropsModule();
        this.modules[1] = new SignedDataObjPropsModule();
        this.modules[2] = new UnsignedSigPropsModule();
        this.modules[3] = new UnsignedDataObjPropsModule();
    }

    @Override
    public void unmarshalProperties(
            Element qualifyingProps,
            QualifyingPropertiesDataCollector propertyDataCollector) throws UnmarshalException
    {
        XmlQualifyingPropertiesType xmlQualifyingProps = null;
        try
        {
            // Create the JAXB unmarshaller.
            JAXBContext jaxbContext = JAXBContext.newInstance(XmlQualifyingPropertiesType.class);
            // Create the JAXB unmarshaller and unmarshalProperties the root JAXB element
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            JAXBElement<XmlQualifyingPropertiesType> qualifPropsElem = (JAXBElement<XmlQualifyingPropertiesType>)unmarshaller.unmarshal(qualifyingProps);
            xmlQualifyingProps = qualifPropsElem.getValue();
        } catch (javax.xml.bind.UnmarshalException ex)
        {
            throw new UnmarshalException("Cannot bind XML elements to Java classes", ex);
        } catch (JAXBException ex)
        {
            throw new UnmarshalException("Cannot unmarshall properties. Error on JAXB unmarshalling.", ex);
        }

        // Iterate the modules to convert the different types of properties.
        for (UnmarshallerModule module : modules)
        {
            module.convertProperties(xmlQualifyingProps, qualifyingProps, propertyDataCollector);
        }
    }

    @Override
    public void setAcceptUnknownProperties(boolean accept)
    {
        for (UnmarshallerModule module : modules)
        {
            module.setAcceptUnknownProperties(accept);
        }
    }
}
