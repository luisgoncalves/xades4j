/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
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
package xades4j.verification;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.w3c.dom.Element;

import com.google.inject.Inject;

import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.PropertiesDataObjectsStructureVerifier;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.PropertyDataStructureException;
import xades4j.xml.unmarshalling.QualifyingPropertiesDataCollector;

public class HybridQualifyingPropertiesVerifierImpl implements
        QualifyingPropertiesVerifier
{
    private final QualifyingPropertyVerifiersMapper propertyVerifiersMapper;
    private final PropertiesDataObjectsStructureVerifier dataObjectsStructureVerifier;

    @Inject
    public HybridQualifyingPropertiesVerifierImpl(
            QualifyingPropertyVerifiersMapper propVerMapp,
            PropertiesDataObjectsStructureVerifier dataObjStructVerif)
    {
        propertyVerifiersMapper = propVerMapp;
        dataObjectsStructureVerifier = dataObjStructVerif;
    }

    @Override
    public Collection<PropertyInfo> verifyProperties(
            QualifyingPropertiesDataCollector dataCollector,
            QualifyingPropertyVerificationContext ctx)
            throws PropertyDataStructureException, InvalidPropertyException,
            QualifyingPropertyVerifierNotAvailableException
    {
        /*
         * new invocation method (one that knows about XML structure of properties
         */

        // verify internal data structure of properties (presence of mandatory elements
        // and sanity of all elements)
        List<PropertyDataObject> unmarshalledProperties = dataCollector.getPropertiesData();
        dataObjectsStructureVerifier.verifiyPropertiesDataStructure(unmarshalledProperties);

        Collection<PropertyInfo> props = new ArrayList<PropertyInfo>(unmarshalledProperties.size());

        for (PropertyDataObject propData : unmarshalledProperties)
        {
            QualifyingPropertyVerifier<PropertyDataObject> propVerifier =
                    this.propertyVerifiersMapper.getVerifier(propData);
            Element elem = (Element) dataCollector.getPropertyNode(propData);
            QualifyingProperty p = propVerifier.verify(propData, elem, ctx);
            if (p == null)
                throw new PropertyVerifierErrorException(propData.getClass().getName());

            props.add(new PropertyInfo(propData, p));
        }

        return Collections.unmodifiableCollection(props);
    }

    @Deprecated
    @Override
    public Collection<PropertyInfo> verifyProperties(
            List<PropertyDataObject> unmarshalledProperties,
            QualifyingPropertyVerificationContext ctx)
            throws PropertyDataStructureException, InvalidPropertyException,
            QualifyingPropertyVerifierNotAvailableException
    {
        // old invocation method so use old implementation
        QualifyingPropertiesVerifier qpv = new QualifyingPropertiesVerifierImpl(
                propertyVerifiersMapper,
                dataObjectsStructureVerifier);

        return qpv.verifyProperties(unmarshalledProperties, ctx);
    }

}
