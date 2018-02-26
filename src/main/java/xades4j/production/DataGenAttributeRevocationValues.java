/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Hubert Kario - QBS
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
package xades4j.production;

import java.security.cert.CRLException;
import java.security.cert.X509CRL;

import xades4j.properties.AttributeRevocationValuesProperty;
import xades4j.properties.data.AttributeRevocationValuesData;
import xades4j.properties.data.PropertyDataObject;

/**
 *
 * @author Hubert Kario
 *
 */
public class DataGenAttributeRevocationValues implements
        PropertyDataObjectGenerator<AttributeRevocationValuesProperty>
{
    @Override
    public PropertyDataObject generatePropertyData(
            AttributeRevocationValuesProperty prop,
            PropertiesDataGenerationContext ctx)
            throws PropertyDataGenerationException
    {
        AttributeRevocationValuesData attrRevocValuesData = new AttributeRevocationValuesData();
        try
        {
            for (X509CRL crl : prop.getCrls())
            {
                attrRevocValuesData.addData(crl.getEncoded());
            }
        } catch (CRLException ex)
        {
            throw new PropertyDataGenerationException(prop, "cannot get encoded CRL", ex);
        }
        return attrRevocValuesData;
    }
}
