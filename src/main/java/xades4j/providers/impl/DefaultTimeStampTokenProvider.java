/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Luis Goncalves.
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
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import xades4j.UnsupportedAlgorithmException;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.TimeStampTokenGenerationException;
import xades4j.providers.TimeStampTokenProvider;
import xades4j.providers.TimeStampTokenProvider.TimeStampTokenRes;

/**
 * Default implementation of {@code TimeStampTokenProvider}. Issues time-stamp
 * requests (with {@code certReq} set to {@code true}) over HTTP. The TSA URL can
 * be overriden.
 * @author Luís
 */
public class DefaultTimeStampTokenProvider implements TimeStampTokenProvider
{
    private static final Map<String, ASN1ObjectIdentifier> digestUriToOidMappings;
    static
    {
        digestUriToOidMappings = new HashMap<String, ASN1ObjectIdentifier>(6);
        digestUriToOidMappings.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5, TSPAlgorithms.MD5);
        digestUriToOidMappings.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_RIPEMD160, TSPAlgorithms.RIPEMD160);
        digestUriToOidMappings.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1, TSPAlgorithms.SHA1);
        digestUriToOidMappings.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256, TSPAlgorithms.SHA256);
        digestUriToOidMappings.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384, TSPAlgorithms.SHA384);
        digestUriToOidMappings.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512, TSPAlgorithms.SHA512);
    }

    // TODO this probably should be a provider to avoid being dependent on a fixed set of algorithms
    private static ASN1ObjectIdentifier identifierForDigest(String digestAlgUri)
    {
        return digestUriToOidMappings.get(digestAlgUri);
    }
    /****/
    private final MessageDigestEngineProvider messageDigestProvider;
    private final TimeStampRequestGenerator tsRequestGenerator;
    private final String tsaUrl;

    @Inject
    public DefaultTimeStampTokenProvider(MessageDigestEngineProvider messageDigestProvider)
    {
        this(messageDigestProvider, "http://tss.accv.es:8318/tsa");
    }

    DefaultTimeStampTokenProvider(MessageDigestEngineProvider messageDigestProvider, String tsaUrl)
    {
        this.messageDigestProvider = messageDigestProvider;
        this.tsaUrl = tsaUrl;
        this.tsRequestGenerator = new TimeStampRequestGenerator();
        this.tsRequestGenerator.setCertReq(true);
    }

    @Override
    public final TimeStampTokenRes getTimeStampToken(
            byte[] tsDigestInput,
            String digestAlgUri) throws TimeStampTokenGenerationException
    {
        try
        {
            MessageDigest md = messageDigestProvider.getEngine(digestAlgUri);
            byte[] digest = md.digest(tsDigestInput);

            TimeStampRequest tsRequest = this.tsRequestGenerator.generate(
                    identifierForDigest(digestAlgUri),
                    digest,
                    BigInteger.valueOf(System.currentTimeMillis()));
            InputStream responseStream = getResponse(tsRequest.getEncoded());
            TimeStampResponse tsResponse = new TimeStampResponse(responseStream);

            if(tsResponse.getStatus() != PKIStatus.GRANTED &&
               tsResponse.getStatus() != PKIStatus.GRANTED_WITH_MODS)
            {
                throw new TimeStampTokenGenerationException("Time stamp token not granted. " + tsResponse.getStatusString());
            }
            tsResponse.validate(tsRequest);

            TimeStampToken tsToken = tsResponse.getTimeStampToken();
            return new TimeStampTokenRes(tsToken.getEncoded(), tsToken.getTimeStampInfo().getGenTime());
        }
        catch (UnsupportedAlgorithmException ex)
        {
            throw new TimeStampTokenGenerationException("Digest algorithm not supported", ex);
        } catch (TSPException ex)
        {
            throw new TimeStampTokenGenerationException("Invalid time stamp response", ex);
        } catch (IOException ex)
        {
            throw new TimeStampTokenGenerationException("Encoding error", ex);
        }
    }

    private InputStream getResponse(byte[] encodedRequest) throws TimeStampTokenGenerationException
    {
        try
        {
            HttpURLConnection connection = getHttpConnection();
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-type", "application/timestamp-query");
            connection.setRequestProperty("Content-length", String.valueOf(encodedRequest.length));

            OutputStream out = connection.getOutputStream();
            out.write(encodedRequest);
            out.flush();

            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK)
            {
                throw new TimeStampTokenGenerationException(String.format("TSA returned HTTP %d %s", connection.getResponseCode(), connection.getResponseMessage()));
            }

            // TODO do we need to invoke connection.disconnect()?
            return new BufferedInputStream(connection.getInputStream());
        }
        catch (IOException ex)
        {
            throw new TimeStampTokenGenerationException("Error when connecting to the TSA", ex);
        }
    }

    HttpURLConnection getHttpConnection() throws IOException
    {
        URL url = new URL(getTSAUrl());
        return (HttpURLConnection) url.openConnection();
    }

    /**
     * Gets the TSA URL. Override
     * to change the TSA in use.
     * @return the url (default is {@code http://tss.accv.es:8318/tsa}
     */
    protected String getTSAUrl()
    {
        return this.tsaUrl;
    }
}
