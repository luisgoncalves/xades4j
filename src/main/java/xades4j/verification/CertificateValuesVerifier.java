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

import java.security.cert.X509Certificate;
import java.util.Collection;

import org.w3c.dom.Element;

import com.google.inject.Inject;

import xades4j.properties.CertificateValuesProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.CertificateValuesData;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.TSACertificateValidationProvider;

/**
 *
 * @author Hubert Kario
 *
 */
public class CertificateValuesVerifier extends EncapsulatedPKIDataVerifierBase<CertificateValuesData>
{
    @Inject
    public CertificateValuesVerifier(String propName)
    {
        super(propName);
    }

    @Override
    public QualifyingProperty createProperty(Collection<X509Certificate> certs)
    {
        return new CertificateValuesProperty(certs);
    }

    @Override
    public void addCertificatesToValidationProvider(
            Collection<X509Certificate> certificates,
            QualifyingPropertyVerificationContext ctx)
    {
        ctx.addSignatureCertificates(certificates);
    }
}
