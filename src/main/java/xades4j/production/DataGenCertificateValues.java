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
package xades4j.production;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import xades4j.properties.CertificateValuesProperty;
import xades4j.properties.data.CertificateValuesData;
import xades4j.properties.data.PropertyDataObject;

/**
 *
 * @author Luís
 */
class DataGenCertificateValues implements PropertyDataObjectGenerator<CertificateValuesProperty>
{
    @Override
    public PropertyDataObject generatePropertyData(
            CertificateValuesProperty prop,
            PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException
    {
        CertificateValuesData certValuesData = new CertificateValuesData();
        try
        {
            for (X509Certificate cer : prop.getCertificates())
            {
                certValuesData.addData(cer.getEncoded());
            }
        } catch (CertificateEncodingException ex)
        {
            throw new PropertyDataGenerationException(prop, "cannot get encoded certificate", ex);
        }
        return certValuesData;
    }
}
