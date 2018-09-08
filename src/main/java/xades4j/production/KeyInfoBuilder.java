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
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.Transforms;
import xades4j.UnsupportedAlgorithmException;
import xades4j.algorithms.Algorithm;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.X500NameStyleProvider;
import xades4j.utils.CanonicalizerUtils;
import xades4j.utils.TransformUtils;
import xades4j.xml.marshalling.algorithms.AlgorithmsParametersMarshallingProvider;

/**
 * Helper class that creates the {@code ds:KeyInfo} element accordingly to some
 * signature options. The signing certificate validity and key usages are
 * validated.
 *
 * @author Luís
 */
class KeyInfoBuilder
{
    private final BasicSignatureOptions basicSignatureOptions;
    private final AlgorithmsProviderEx algorithmsProvider;
    private final AlgorithmsParametersMarshallingProvider algorithmsParametersMarshaller;
    private final X500NameStyleProvider x500NameStyleProvider;

    KeyInfoBuilder(
            BasicSignatureOptions basicSignatureOptions,
            AlgorithmsProviderEx algorithmsProvider,
            AlgorithmsParametersMarshallingProvider algorithmsParametersMarshaller,
            X500NameStyleProvider x500NameStyleProvider)
    {
        this.basicSignatureOptions = basicSignatureOptions;
        this.algorithmsProvider = algorithmsProvider;
        this.algorithmsParametersMarshaller = algorithmsParametersMarshaller;
        this.x500NameStyleProvider = x500NameStyleProvider;
    }

    void buildKeyInfo(
            X509Certificate signingCertificate,
            XMLSignature xmlSig) throws KeyingDataException, UnsupportedAlgorithmException
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

        if (this.basicSignatureOptions.includeSigningCertificate()
            || this.basicSignatureOptions.includeIssuerSerial()
            || this.basicSignatureOptions.includeSubjectName())
        {
            X509Data x509Data = new X509Data(xmlSig.getDocument());
            xmlSig.getKeyInfo().add(x509Data);

            if (this.basicSignatureOptions.includeSigningCertificate())
            {
                try
                {
                    x509Data.addCertificate(signingCertificate);
                } 
                catch (XMLSecurityException ex)
                {
                    throw new KeyingDataException(ex.getMessage(), ex);
                }
            }

            if (this.basicSignatureOptions.includeIssuerSerial())
            {
                x509Data.addIssuerSerial(this.x500NameStyleProvider.toString(signingCertificate.getIssuerX500Principal()), signingCertificate.getSerialNumber());
            }

            if (this.basicSignatureOptions.includeSubjectName())
            {
                x509Data.addSubjectName(this.x500NameStyleProvider.toString(signingCertificate.getSubjectX500Principal()));
            }
        }

        if (this.basicSignatureOptions.includePublicKey())
        {
            xmlSig.addKeyInfo(signingCertificate.getPublicKey());
        }

        if (this.basicSignatureOptions.signKeyInfo())
        {
            try
            {
                String keyInfoId = xmlSig.getId() + "-keyinfo";
                xmlSig.getKeyInfo().setId(keyInfoId);

                // Use same canonicalization URI as specified in the ds:CanonicalizationMethod for Signature.
                Algorithm canonAlg = this.algorithmsProvider.getCanonicalizationAlgorithmForSignature();
                CanonicalizerUtils.checkC14NAlgorithm(canonAlg);
                Transforms transforms = TransformUtils.createTransforms(canonAlg, this.algorithmsParametersMarshaller, xmlSig.getDocument());

                xmlSig.addDocument(
                    '#' + keyInfoId,
                    transforms,
                    this.algorithmsProvider.getDigestAlgorithmForDataObjsReferences());
            }
            catch (XMLSignatureException ex)
            {
                throw new UnsupportedAlgorithmException(
                    "Digest algorithm not supported in the XML Signature provider",
                    this.algorithmsProvider.getDigestAlgorithmForDataObjsReferences(), ex);
            }
        }
    }
}
