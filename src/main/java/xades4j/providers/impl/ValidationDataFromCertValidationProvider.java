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
package xades4j.providers.impl;

import xades4j.providers.*;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import xades4j.XAdES4jException;

/**
 * An implementation of {@code ValidationDataProvider} that obtains the validation
 * data by validating the certificate.
 * @author Luís
 */
public class ValidationDataFromCertValidationProvider implements ValidationDataProvider
{
    private final CertificateValidationProvider certificateValidationProvider;

    public ValidationDataFromCertValidationProvider(
            CertificateValidationProvider certificateValidationProvider)
    {
        this.certificateValidationProvider = certificateValidationProvider;
    }

    @Override
    public ValidationData getValidationData(
            List<X509Certificate> certChainFragment) throws ValidationDataException
    {
        try
        {
            X509CertSelector cs = new X509CertSelector();
            cs.setCertificate(certChainFragment.get(0));
            return this.certificateValidationProvider.validate(cs, new Date(), certChainFragment);
        } catch (XAdES4jException ex)
        {
            throw new ValidationDataException("Cannot validate certificate to obtain validation data", ex);
        }
    }
}
