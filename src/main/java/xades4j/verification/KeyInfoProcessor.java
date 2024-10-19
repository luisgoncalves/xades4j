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

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import xades4j.properties.data.CertRef;
import xades4j.providers.CertificateValidationException;
import xades4j.providers.X500NameStyleProvider;

import javax.annotation.Nullable;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * @author Luís
 */
class KeyInfoProcessor
{
    private KeyInfoProcessor()
    {
    }
    /**/

    static class KeyInfoRes
    {
        final X509CertSelector signingCertSelector;
        final boolean signingCertSelectorFromKeyInfo;
        final List<X509Certificate> certs;
        @Nullable
        final XMLX509IssuerSerial issuerSerial;

        private KeyInfoRes(
                X509CertSelector signingCertSelector,
                boolean signingCertSelectorFromKeyInfo,
                List<X509Certificate> certs,
                @Nullable XMLX509IssuerSerial issuerSerial)
        {
            this.signingCertSelector = signingCertSelector;
            this.signingCertSelectorFromKeyInfo = signingCertSelectorFromKeyInfo;
            this.certs = certs;
            this.issuerSerial = issuerSerial;
        }
    }

    static KeyInfoRes process(
            KeyInfo keyInfo, @Nullable CertRef signingCertRef, X500NameStyleProvider x500NameStyleProvider) throws CertificateValidationException
    {
        if (null == keyInfo || !keyInfo.containsX509Data())
        {
            return tryUseSigningCertificateReference(signingCertRef, x500NameStyleProvider);
        }

        List<X509Certificate> keyInfoCerts = new ArrayList<>(1);
        XMLX509IssuerSerial issuerSerial = null;
        X509CertSelector signingCertSelector = new X509CertSelector();

        // XML-DSIG 4.4.4: "Any X509IssuerSerial, X509SKI, and X509SubjectName elements
        // that appear MUST refer to the certificate or certificates containing the
        // validation key."
        // "All certificates appearing in an X509Data element MUST relate to the
        // validation key by either containing it or being part of a certification
        // chain that terminates in a certificate containing the validation key".

        // Scan ds:X509Data to find ds:IssuerSerial or ds:SubjectName elements. The
        // first to be found is used to select the leaf certificate. If none of those
        // elements is present, the first ds:X509Certificate is assumed as the signing
        // certificate.
        boolean hasSelectionCriteria = false;

        try
        {
            for (int i = 0; i < keyInfo.lengthX509Data(); ++i)
            {
                X509Data x509Data = keyInfo.itemX509Data(i);

                if (!hasSelectionCriteria)
                {
                    if (x509Data.containsIssuerSerial())
                    {
                        issuerSerial = x509Data.itemIssuerSerial(0);
                        signingCertSelector.setIssuer(x500NameStyleProvider.fromString(issuerSerial.getIssuerName()));
                        signingCertSelector.setSerialNumber(issuerSerial.getSerialNumber());
                        hasSelectionCriteria = true;
                    }
                    else if (x509Data.containsSubjectName())
                    {
                        signingCertSelector.setSubject(x500NameStyleProvider.fromString(x509Data.itemSubjectName(0).getSubjectName()));
                        hasSelectionCriteria = true;
                    }
                }

                // Collect all certificates as they may be needed to build the cert path.
                if (x509Data.containsCertificate())
                {
                    for (int j = 0; j < x509Data.lengthCertificate(); ++j)
                    {
                        keyInfoCerts.add(x509Data.itemCertificate(j).getX509Certificate());
                    }
                }
            }

            if (!hasSelectionCriteria && !keyInfoCerts.isEmpty())
            {
                signingCertSelector.setCertificate(keyInfoCerts.get(0));
                hasSelectionCriteria = true;
            }
        }
        catch (XMLSecurityException ex)
        {
            throw new InvalidKeyInfoDataException("Cannot process X509Data", ex);
        }

        return hasSelectionCriteria
                ? new KeyInfoRes(signingCertSelector, true, keyInfoCerts, issuerSerial)
                : tryUseSigningCertificateReference(signingCertRef, x500NameStyleProvider);
    }

    private static KeyInfoRes tryUseSigningCertificateReference(CertRef signingCertRef, X500NameStyleProvider x500NameStyleProvider) throws CertificateValidationException
    {
        if (signingCertRef == null)
        {
            throw new InvalidKeyInfoDataException("Could not identify the leaf certificate using X509Datas in KeyInfo");
        }

        X509CertSelector certSelector = new X509CertSelector();
        certSelector.setIssuer(x500NameStyleProvider.fromString(signingCertRef.getIssuerDN()));
        certSelector.setSerialNumber(signingCertRef.getSerialNumber());

        return new KeyInfoRes(certSelector, false, Collections.emptyList(), null);
    }
}
