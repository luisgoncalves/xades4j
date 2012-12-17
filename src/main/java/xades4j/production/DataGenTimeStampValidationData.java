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
package xades4j.production;

import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import xades4j.properties.TimeStampValidationDataProperty;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.TimeStampValidationDataData;

/**
 *
 * @author Hubert Kario
 *
 */
public class DataGenTimeStampValidationData implements
        PropertyDataObjectGenerator<TimeStampValidationDataProperty>
{

    @Override
    public PropertyDataObject generatePropertyData(
            TimeStampValidationDataProperty prop,
            PropertiesDataGenerationContext ctx)
            throws PropertyDataGenerationException
    {
        TimeStampValidationDataData tsValidationDataData =
                new TimeStampValidationDataData();

        try
        {
            for (X509Certificate cer : prop.getCertificates())
            {
                tsValidationDataData.addCertificateData(cer.getEncoded());
            }
        } catch (CertificateEncodingException e)
        {
            throw new PropertyDataGenerationException(prop, "cannot get encoded certificate", e);
        }

        try
        {
            for (X509CRL crl : prop.getCrls())
            {
                tsValidationDataData.addCRLData(crl.getEncoded());
            }
        } catch (CRLException e)
        {
            throw new PropertyDataGenerationException(prop, "cannot get encoded CRL", e);
        }

        return tsValidationDataData;
    }

}
