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
package xades4j.properties.data;

import java.util.Collection;

public class BaseValidationDataData implements PropertyDataObject
{
    private final CertificateValuesData certificateValues;
    private final RevocationValuesData crlData;

    public BaseValidationDataData(
            Collection<byte[]> certificates,
            Collection<byte[]> crlData)
    {
        this.certificateValues = new CertificateValuesData(certificates);
        this.crlData = new RevocationValuesData(crlData);
    }

    public BaseValidationDataData()
    {
        this.certificateValues = new CertificateValuesData();
        this.crlData = new RevocationValuesData();
    }

    public void addCertificateData(byte[] d)
    {
        this.certificateValues.addData(d);
    }

    public void addCRLData(byte[] d)
    {
        this.crlData.addData(d);
    }

    public Collection<byte[]> getCertificateData()
    {
        return certificateValues.getData();
    }

    public Collection<byte[]> getCRLData()
    {
        return crlData.getData();
    }
}
