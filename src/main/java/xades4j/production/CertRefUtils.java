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
package xades4j.production;

import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import xades4j.UnsupportedAlgorithmException;
import xades4j.properties.data.BaseCertRefsData;
import xades4j.properties.data.CertRef;
import xades4j.providers.AlgorithmsProvider;
import xades4j.providers.MessageDigestEngineProvider;

/**
 *
 * @author Luís
 */
class CertRefUtils
{
    private CertRefUtils()
    {
    }

    static void createAndAddCertificateReferences(
            Collection<X509Certificate> certs,
            BaseCertRefsData certRefsData,
            AlgorithmsProvider algsProv,
            MessageDigestEngineProvider digestProv) throws UnsupportedAlgorithmException, CertificateEncodingException
    {
        String digestAlgUri = algsProv.getDigestAlgorithmForReferenceProperties();
        MessageDigest messageDigest = digestProv.getEngine(digestAlgUri);

        for (X509Certificate cert : certs)
        {
            // "DigestValue contains the base-64 encoded value of the digest
            // computed on the DER-encoded certificate."
            // The base-64 encoding is done by JAXB with the configured
            // adapter (Base64XmlAdapter).
            // For X509 certificates the encoded form return by getEncoded is DER.
            byte[] digestValue = messageDigest.digest(cert.getEncoded());

            certRefsData.addCertRef(new CertRef(
                    cert.getIssuerX500Principal().getName(),
                    cert.getSerialNumber(),
                    digestAlgUri,
                    digestValue));
        }
    }
}
