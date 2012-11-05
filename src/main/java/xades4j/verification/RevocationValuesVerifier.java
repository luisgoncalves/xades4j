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
package xades4j.verification;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import xades4j.properties.QualifyingProperty;
import xades4j.properties.RevocationValuesProperty;
import xades4j.properties.data.RevocationValuesData;

public class RevocationValuesVerifier implements
        QualifyingPropertyVerifier<RevocationValuesData>
{

    @Override
    public QualifyingProperty verify(RevocationValuesData propData,
            QualifyingPropertyVerificationContext ctx)
            throws InvalidPropertyException
    {
        Collection<byte[]> rawRevocationData = propData.getData();
        CertificateFactory certFactory;
        try
        {
            certFactory = CertificateFactory.getInstance("X509");
        } catch (CertificateException ex)
        {
            throw new RevocationValuesVerificationException(ex);
        }

        List<X509CRL> crls = new ArrayList<X509CRL>();

        for (byte[] crl : rawRevocationData)
        {
            InputStream inStream = new ByteArrayInputStream(crl);
            try
            {
                crls.add((X509CRL) certFactory.generateCRL(inStream));
            } catch (CRLException ex)
            {
                throw new RevocationValuesVerificationException(ex);
            }
        }

        return new RevocationValuesProperty(crls);
    }

}
