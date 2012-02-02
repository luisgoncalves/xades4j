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

import com.google.inject.Inject;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import xades4j.XAdES4jException;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.TimeStampTokenDigestException;
import xades4j.providers.TimeStampTokenSignatureException;
import xades4j.providers.TimeStampTokenStructureException;
import xades4j.providers.TimeStampTokenTSACertException;
import xades4j.providers.TimeStampTokenVerificationException;
import xades4j.providers.TimeStampVerificationProvider;
import xades4j.providers.ValidationData;
import xades4j.utils.TimeStampTokenInfo;

/**
 * Default implementation of {@code TimeStampVerificationProvider}. It verifies
 * the token signature, including the TSA certificate, and the digest imprint.
 * <p>
 * It uses the SUN proprietary API in the {@code sun.security.pkcs} package
 * to parse the token and access its members. <b>Only supports DER-encoded tokens</b>.
 * @author Luís
 */
public class DefaultTimeStampVerificationProvider implements TimeStampVerificationProvider
{

    private final CertificateValidationProvider certificateValidationProvider;

    @Inject
    public DefaultTimeStampVerificationProvider(CertificateValidationProvider certificateValidationProvider)
    {
        this.certificateValidationProvider = certificateValidationProvider;
    }

    @Override
    public Date verifyToken(byte[] timeStampToken, byte[] tsDigestInput) throws TimeStampTokenVerificationException
    {
        PKCS7 token;
        TimeStampTokenInfo tstInfo;
        try
        {
            token = new PKCS7(timeStampToken);
            tstInfo = new TimeStampTokenInfo(token.getContentInfo().getContentBytes());
        } catch (IOException ex)
        {
            throw new TimeStampTokenStructureException("Invalid token", ex);
        }

        SignerInfo[] signerInfos = token.getSignerInfos();
        // RFC 3161: "The time-stamp token MUST NOT contain any signatures
        // other than the signature of the TSA."
        if (null == signerInfos || signerInfos.length != 1)
        {
            throw new TimeStampTokenStructureException("Only one signature should be present on time-stamp token");
        }

        X509Certificate[] tokenCerts = token.getCertificates();
        SignerInfo tsaSignerInfo = signerInfos[0];

        /* Validate the TSA certificate */

        X509CertSelector tsaCertSelector = new X509CertSelector();
        tsaCertSelector.setIssuer(new X500Principal(tsaSignerInfo.getIssuerName().getName()));
        tsaCertSelector.setSerialNumber(tsaSignerInfo.getCertificateSerialNumber());

        ValidationData vData;
        try
        {
            vData = this.certificateValidationProvider.validate(
                    tsaCertSelector,
                    tstInfo.getDate(),
                    null == tokenCerts ? null : Arrays.asList(tokenCerts));
        } catch (XAdES4jException ex)
        {
            throw new TimeStampTokenTSACertException("cannot validate TSA certificate", ex);
        }

        /* Verify the token's signature */

        // If the token had no certificates, clone it using the certificate
        // on the certification path. This way 'token.verify' can always be used.
        if (null == tokenCerts)
        {
            token = new PKCS7(
                    token.getDigestAlgorithmIds(),
                    token.getContentInfo(),
                    new X509Certificate[]
                    {
                        vData.getCerts().get(0)
                    },
                    signerInfos);
        }
        try
        {
            // Verify the signature.
            if (null == token.verify(tsaSignerInfo, null))
            {
                throw new TimeStampTokenSignatureException("Time-stamp token signature is not valid");
            }

        } catch (GeneralSecurityException ex)
        {
            // NoSuchAlgorithmException
            // SignatureException
            throw new TimeStampTokenSignatureException("Time-stamp token signature is not valid", ex);
        }

        /* Verify the token's input digest */

        try
        {
            
            MessageDigest md = MessageDigest.getInstance(tstInfo.getHashAlgorithm().getName());
            if (!Arrays.equals(md.digest(tsDigestInput), tstInfo.getHashedMessage()))
            {
                throw new TimeStampTokenDigestException();
            }

        } catch (NoSuchAlgorithmException ex)
        {
            throw new TimeStampTokenVerificationException("The token's digest algorithm is not supported", ex);
        }
        
        return tstInfo.getDate();
    }
}
