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
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import sun.security.timestamp.HttpTimestamper;
import sun.security.timestamp.TSRequest;
import sun.security.timestamp.TSResponse;
import sun.security.timestamp.Timestamper;
import xades4j.UnsupportedAlgorithmException;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.TimeStampTokenGenerationException;
import xades4j.providers.TimeStampTokenProvider;
import xades4j.providers.TimeStampTokenProvider.TimeStampTokenRes;
import xades4j.utils.TimeStampTokenInfo;

/**
 * Default implementation of {@code TimeStampTokenProvider}. It uses the SUN proprietary
 * API in the {@code sun.security.timestamp} and {@code sun.security.pkcs} packages.
 * By default it used simple HTTP to get the time-stamp token from the TSA at
 * {@code http://tss.accv.es:8318/tsa}. Both the {@code Timestamper} and the TSA
 * URL can be overriden.
 * <p>
 * The TSA certificate is requested. If the token is granted with mods, a check
 * is made to ensure that the mod wasn't not providing the certificate. If so, an
 * exception is thrown.
 * @author Luís
 */
public class DefaultTimeStampTokenProvider implements TimeStampTokenProvider
{
    private final MessageDigestEngineProvider messageDigestProvider;

    @Inject
    public DefaultTimeStampTokenProvider(
            MessageDigestEngineProvider messageDigestProvider)
    {
        this.messageDigestProvider = messageDigestProvider;
    }

    @Override
    public final TimeStampTokenRes getTimeStampToken(
            byte[] tsDigestInput,
            String digestAlgUri) throws TimeStampTokenGenerationException
    {
        MessageDigest md;
        try
        {
            md = messageDigestProvider.getEngine(digestAlgUri);
        } catch (UnsupportedAlgorithmException ex)
        {
            throw new TimeStampTokenGenerationException(ex.getMessage());
        }

        byte[] digest = md.digest(tsDigestInput);

        TSRequest tsReq = new TSRequest(digest, md.getAlgorithm());
        tsReq.requestCertificate(true);
        TSResponse tsRes;
        try
        {
            tsRes = getTimestamper().generateTimestamp(tsReq);
        } catch (IOException ex)
        {
            throw new TimeStampTokenGenerationException("no TSA response");
        }

        PKCS7 token = tsRes.getToken();
        if (null == token)
            // Time-stamp not granted.
            throw new TimeStampTokenGenerationException(tsRes.getFailureCodeAsText());

        SignerInfo[] signerInfos = token.getSignerInfos();
        if (null == signerInfos || signerInfos.length != 1)
            // RFC 3161: "The time-stamp token MUST NOT contain any signatures
            // other than the signature of the TSA."
            throw new TimeStampTokenGenerationException("Only one signature should be present on time-stamp token");

        if (tsRes.getStatusCode() == TSResponse.GRANTED_WITH_MODS)
        {
            // Check that the TSA certificate is present despite the modification.
            X509Certificate[] certs = token.getCertificates();
            if (null == certs || certs.length == 0)
                throw new TimeStampTokenGenerationException("TSA certificate wasn't included in the time-stamp response");
        }

        TimeStampTokenInfo tstInfo;
        try
        {
            tstInfo = new TimeStampTokenInfo(token.getContentInfo().getContentBytes());
        } catch (IOException ex)
        {
            throw new TimeStampTokenGenerationException(ex.getMessage());
        }

        return new TimeStampTokenRes(tsRes.getEncodedToken(), tstInfo.getDate());
    }

    /**
     * Gets the {@code Timestamper to be used}. Override to change this behaviour.
     * By default, this method invokes {@code getTSAUrl} to create an {@code HttpTimestamper}.
     * @return the timestamper
     */
    protected Timestamper getTimestamper()
    {
        return new HttpTimestamper(getTSAUrl());
    }

    /**
     * Gets the TSA URL when the default {@code HttpTimestamper} is used. Override
     * to change the TSA in use.
     * @return the url (default is {@code http://tss.accv.es:8318/tsa}
     */
    protected String getTSAUrl()
    {
        return "http://tss.accv.es:8318/tsa";
    }
}
