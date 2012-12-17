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
    private final RevocationValuesData revocationData;

    public BaseValidationDataData(
            Collection<byte[]> certificates,
            Collection<byte[]> revocationData)
    {
        this.certificateValues = new CertificateValuesData(certificates);
        this.revocationData = new RevocationValuesData(revocationData);
    }

    public BaseValidationDataData()
    {
        this.certificateValues = new CertificateValuesData();
        this.revocationData = new RevocationValuesData();
    }

    public void addCertificateData(byte[] d)
    {
        this.certificateValues.addData(d);
    }

    public void addRevocationData(byte[] d)
    {
        this.revocationData.addData(d);
    }

    public Collection<byte[]> getCertificateData()
    {
        return certificateValues.getData();
    }

    public Collection<byte[]> getRevocationData()
    {
        return revocationData.getData();
    }
}
