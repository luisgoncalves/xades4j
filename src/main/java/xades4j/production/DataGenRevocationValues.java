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

import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import xades4j.properties.RevocationValuesProperty;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.RevocationValuesData;

/**
 *
 * @author Luís
 */
class DataGenRevocationValues implements PropertyDataObjectGenerator<RevocationValuesProperty>
{
    @Override
    public PropertyDataObject generatePropertyData(
            RevocationValuesProperty prop,
            PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException
    {
        RevocationValuesData revocValuesData = new RevocationValuesData();
        try
        {
            for (X509CRL crl : prop.getCrls())
            {
                revocValuesData.addData(crl.getEncoded());
            }
        } catch (CRLException ex)
        {
            throw new PropertyDataGenerationException(ex.getMessage(), prop);
        }
        return revocValuesData;
    }
}
