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
                throw new SigningCertificateVerificationException()
                {
                    @Override
                    protected String getVerificationMessage()
                    {
                        return String.format("Issuer %s has some unrecognized elements", certRef.issuerDN);
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
