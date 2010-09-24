/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA
 */
package xades4j.production;

import xades4j.properties.UnsignedProperties;
import xades4j.properties.SignedProperties;
import com.google.inject.Inject;
import java.util.ArrayList;
import java.util.Collection;
import xades4j.properties.QualifyingProperty;
import xades4j.utils.SigAndDataObjPropsPair;
import xades4j.properties.data.PropertiesDataObjectsStructureVerifier;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.PropertyDataStructureException;
import xades4j.properties.data.SigAndDataObjsPropertiesData;

/**
 *
 * @author Luís
 */
class PropertiesDataObjectsGeneratorImpl implements PropertiesDataObjectsGenerator
{
    private final PropertyDataGeneratorsMapper propsDataGensMapper;
    private final PropertiesDataObjectsStructureVerifier dataObjectsStructureVerifier;

    @Inject
    PropertiesDataObjectsGeneratorImpl(
            PropertyDataGeneratorsMapper propsDataGensMapper)
    {

        this.propsDataGensMapper = propsDataGensMapper;
        this.dataObjectsStructureVerifier = new PropertiesDataObjectsStructureVerifier();
    }

    @Override
    public SigAndDataObjsPropertiesData generateSignedPropertiesData(
            SignedProperties signedProps,
            PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException, PropertyDataStructureException
    {
        return genPropsData(signedProps, ctx);

    }

    @Override
    public SigAndDataObjsPropertiesData generateUnsignedPropertiesData(
            UnsignedProperties unsignedProps,
            PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException, PropertyDataStructureException
    {
        return genPropsData(unsignedProps, ctx);
    }

    /****************************************************************************/
    private SigAndDataObjsPropertiesData genPropsData(
            SigAndDataObjPropsPair<? extends QualifyingProperty, ? extends QualifyingProperty> props,
            PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException, PropertyDataStructureException
    {
        return new SigAndDataObjsPropertiesData(
                doGenPropsData(props.getSigProps(), ctx),
                doGenPropsData(props.getDataObjProps(), ctx));
    }

    private <TProp extends QualifyingProperty> Collection<PropertyDataObject> doGenPropsData(
            Collection<TProp> props,
            PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException, PropertyDataStructureException
    {
        Collection<PropertyDataObject> propsData = new ArrayList<PropertyDataObject>(props.size());

        for (TProp p : props)
        {
            PropertyDataObjectGenerator<TProp> dataGen = this.propsDataGensMapper.getGenerator(p);
            PropertyDataObject pData = dataGen.generatePropertyData(p, ctx);
            if (null == pData)
                throw new PropertyDataGeneratorErrorException((QualifyingProperty)p);

            propsData.add(pData);
        }

        dataObjectsStructureVerifier.verifiyPropertiesDataStructure(propsData);
        return propsData;
    }
}
