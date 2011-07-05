/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2011 Luis Goncalves.
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

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import xades4j.providers.BasicSignatureOptionsProvider;

/**
 * Helper class that creates the {@code ds:KeyInfo} element accordingly to some
 * signature options. The signing certificate validity and key usages are validated.
 * @author Luís
 */
class KeyInfoBuilder
{

    private final BasicSignatureOptionsProvider basicSignatureOptionsProvider;

    KeyInfoBuilder(BasicSignatureOptionsProvider basicSignatureOptionsProvider)
    {
        this.basicSignatureOptionsProvider = basicSignatureOptionsProvider;
    }

    void buildKeyInfo(
            X509Certificate signingCertificate,
            XMLSignature xmlSig) throws KeyingDataException
    {
        // Check key usage.
        // - KeyUsage[0] = digitalSignature
        // - KeyUsage[1] = nonRepudiation
        boolean[] keyUsage = signingCertificate.getKeyUsage();
        if (keyUsage != null && !keyUsage[0] && !keyUsage[1])
        {
            throw new SigningCertKeyUsageException(signingCertificate);
        }

        try
        {
            signingCertificate.checkValidity();
        } catch (CertificateException ce)
        {
            // CertificateExpiredException or CertificateNotYetValidException
            throw new SigningCertValidityException(signingCertificate);
        }

        if (this.basicSignatureOptionsProvider.includeSigningCertificate())
        {
            try
            {
                xmlSig.addKeyInfo(signingCertificate);
            } catch (XMLSecurityException ex)
            {
                throw new KeyingDataException(ex.getMessage(), ex);
            }
        }

        if (this.basicSignatureOptionsProvider.includePublicKey())
        {
            xmlSig.addKeyInfo(signingCertificate.getPublicKey());
        }
    }
}
