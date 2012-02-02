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
package xades4j.verification;

import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import javax.security.auth.x500.X500Principal;
import xades4j.UnsupportedAlgorithmException;
import xades4j.XAdES4jException;
import xades4j.properties.data.CertRef;
import xades4j.providers.MessageDigestEngineProvider;

/**
 *
 * @author Luís
 */
class CertRefUtils
{
    static CertRef findCertRef(
            X509Certificate cert,
            Collection<CertRef> certRefs) throws SigningCertificateVerificationException
    {
        for (final CertRef certRef : certRefs)
        {
            // Need to use a X500Principal because the DN strings can have different
            // spaces and so on.
            X500Principal certRefIssuerPrincipal;
            try
            {
                certRefIssuerPrincipal = new X500Principal(certRef.issuerDN);
            } catch (IllegalArgumentException ex)
            {
                throw new SigningCertificateVerificationException(ex)
                {
                    @Override
                    protected String getVerificationMessage()
                    {
                        return String.format("Invalid issue name: %s", certRef.issuerDN);
                    }
                };
            }
            if (cert.getIssuerX500Principal().equals(certRefIssuerPrincipal) &&
                    certRef.serialNumber.equals(cert.getSerialNumber()))
                return certRef;
        }
        return null;
    }

    static class InvalidCertRefException extends XAdES4jException
    {
        public InvalidCertRefException(String msg)
        {
            super(msg);
        }
    }

    static void checkCertRef(
            CertRef certRef,
            X509Certificate cert,
            MessageDigestEngineProvider messageDigestProvider) throws InvalidCertRefException
    {
        MessageDigest messageDigest;
        Throwable t = null;
        try
        {
            messageDigest = messageDigestProvider.getEngine(certRef.digestAlgUri);
            byte[] actualDigest = messageDigest.digest(cert.getEncoded());
            if (!Arrays.equals(certRef.digestValue, actualDigest))
                throw new InvalidCertRefException("digests mismatch");
            return;
        } catch (UnsupportedAlgorithmException ex)
        {
            t = ex;
        } catch (CertificateEncodingException ex)
        {
            t = ex;
        }
        throw new InvalidCertRefException(t.getMessage());
    }
}
