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
package xades4j.verification;

import com.google.inject.Inject;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.PropertiesDataObjectsStructureVerifier;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.PropertyDataStructureException;
import xades4j.xml.unmarshalling.QualifyingPropertiesDataCollector;

/**
 *
 * @author Luís
 */
class QualifyingPropertiesVerifierImpl implements QualifyingPropertiesVerifier
{
    private final QualifyingPropertyVerifiersMapper propertyVerifiersMapper;
    private final PropertiesDataObjectsStructureVerifier dataObjectsStructureVerifier;

    @Inject
    QualifyingPropertiesVerifierImpl(
            QualifyingPropertyVerifiersMapper propertyVerifiersMapper,
            PropertiesDataObjectsStructureVerifier dataObjectsStructureVerifier)
    {
        this.propertyVerifiersMapper = propertyVerifiersMapper;
        this.dataObjectsStructureVerifier = dataObjectsStructureVerifier;
    }

    @Override
    public List<PropertyInfo> verifyProperties(
            QualifyingPropertiesDataCollector dataCollector,
            QualifyingPropertyVerificationContext ctx) throws PropertyDataStructureException, InvalidPropertyException, QualifyingPropertyVerifierNotAvailableException
    {
        List<PropertyDataObject> unmarshalledProperties = dataCollector.getPropertiesData();
        return verifyProperties(unmarshalledProperties, ctx);
    }

    @Override
    public List<PropertyInfo> verifyProperties(
            List<PropertyDataObject> unmarshalledProperties,
            QualifyingPropertyVerificationContext ctx)
            throws PropertyDataStructureException, InvalidPropertyException,
            QualifyingPropertyVerifierNotAvailableException
    {
        dataObjectsStructureVerifier.verifiyPropertiesDataStructure(unmarshalledProperties);

        List<PropertyInfo> props = new ArrayList<PropertyInfo>(unmarshalledProperties.size());

        for (PropertyDataObject propData : unmarshalledProperties)
        {
            QualifyingPropertyVerifier<PropertyDataObject> propVerifier = this.propertyVerifiersMapper.getVerifier(propData);

            QualifyingProperty p = propVerifier.verify(propData, ctx);
            if (null == p)
                throw new PropertyVerifierErrorException(propData.getClass().getName());

            props.add(new PropertyInfo(propData, p));
        }

        return Collections.unmodifiableList(props);
    }

    @Override
    public List<PropertyInfo> verifyProperties(
            HybridQualifPropsDataCollectorImpl propsDataCollector,
            QualifyingPropertyVerificationContext qPropsCtx,
            List<PropertyInfo> props)
    {
        throw new UnsupportedOperationException("Use HybridQualifyingPropertiesVerifierImpl");
    }
}
