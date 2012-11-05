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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import xades4j.properties.CertificateValuesProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.CertificateValuesData;

public class CertificateValuesVerifier implements QualifyingPropertyVerifier<CertificateValuesData>
{
    @Override
    public QualifyingProperty verify(CertificateValuesData propData,
            QualifyingPropertyVerificationContext ctx)
            throws InvalidPropertyException
    {
        Collection<byte[]> rawCerts = propData.getData();
        CertificateFactory certFactory;
        try
        {
            certFactory = CertificateFactory.getInstance("X509");
        } catch (CertificateException ex)
        {
            throw new CertificateValuesVerificationException(ex);
        }

        List<X509Certificate> certificates = new ArrayList<X509Certificate>();

        for (byte[] cert : rawCerts)
        {
            InputStream inStream = new ByteArrayInputStream(cert);
            try
            {
                certificates.add((X509Certificate) certFactory.generateCertificate(inStream));
            } catch (CertificateException ex)
            {
                throw new CertificateValuesVerificationException(ex);
            }
        }

        return new CertificateValuesProperty(certificates);
    }

}
