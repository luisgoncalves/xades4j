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
package xades4j.providers.impl;

import xades4j.providers.*;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import xades4j.verification.UnexpectedJCAException;

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
        } catch (CertificateValidationException ex)
        {
            throw new ValidationDataException("Cannot validate certificate: " + ex.getMessage(), ex);
        } catch (UnexpectedJCAException ex)
        {
            throw new ValidationDataException("Cannot validate certificate: " + ex.getMessage(), ex);
        }
    }
}
