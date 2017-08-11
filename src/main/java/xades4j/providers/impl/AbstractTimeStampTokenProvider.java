/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2017 Luis Goncalves.
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
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.*;
import xades4j.UnsupportedAlgorithmException;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.TimeStampTokenGenerationException;
import xades4j.providers.TimeStampTokenProvider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of {@code TimeStampTokenProvider} that gets time-stamp tokens
 * from a TSA. Requests are issued with {@code certReq} set to
 * {@code true}.
 *
 * @author luis
 */
public abstract class AbstractTimeStampTokenProvider implements TimeStampTokenProvider {
    private static final Map<String, ASN1ObjectIdentifier> digestUriToOidMappings;

    static {
        digestUriToOidMappings = new HashMap<String, ASN1ObjectIdentifier>(6);
        digestUriToOidMappings.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5, TSPAlgorithms.MD5);
        digestUriToOidMappings.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_RIPEMD160, TSPAlgorithms.RIPEMD160);
        digestUriToOidMappings.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1, TSPAlgorithms.SHA1);
        digestUriToOidMappings.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256, TSPAlgorithms.SHA256);
        digestUriToOidMappings.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384, TSPAlgorithms.SHA384);
        digestUriToOidMappings.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512, TSPAlgorithms.SHA512);
    }

    // TODO this probably should be a provider to avoid being dependent on a fixed set of algorithms
    private static ASN1ObjectIdentifier identifierForDigest(String digestAlgUri) {
        return digestUriToOidMappings.get(digestAlgUri);
    }

    private final MessageDigestEngineProvider messageDigestProvider;
    private final TimeStampRequestGenerator tsRequestGenerator;

    @Inject
    AbstractTimeStampTokenProvider(MessageDigestEngineProvider messageDigestProvider) {
        this.messageDigestProvider = messageDigestProvider;
        this.tsRequestGenerator = new TimeStampRequestGenerator();
        this.tsRequestGenerator.setCertReq(true);
    }

    @Override
    public final TimeStampTokenRes getTimeStampToken(byte[] tsDigestInput, String digestAlgUri) throws TimeStampTokenGenerationException {
        byte[] digest;
        try {
            MessageDigest md = messageDigestProvider.getEngine(digestAlgUri);
            digest = md.digest(tsDigestInput);
        } catch (UnsupportedAlgorithmException ex) {
            throw new TimeStampTokenGenerationException("Digest algorithm not supported", ex);
        }

        TimeStampRequest tsRequest = this.tsRequestGenerator.generate(
                identifierForDigest(digestAlgUri),
                digest,
                BigInteger.valueOf(System.currentTimeMillis()));

        TimeStampResponse tsResponse = getTimeStampResponse(tsRequest);
        if (tsResponse.getStatus() != PKIStatus.GRANTED && tsResponse.getStatus() != PKIStatus.GRANTED_WITH_MODS) {
            throw new TimeStampTokenGenerationException("Time stamp token not granted. " + tsResponse.getStatusString());
        }

        try {
            tsResponse.validate(tsRequest);
        } catch (TSPException ex) {
            throw new TimeStampTokenGenerationException("Invalid time stamp response", ex);
        }

        TimeStampToken tsToken = tsResponse.getTimeStampToken();
        TimeStampTokenRes tsTokenRes;
        try {
            tsTokenRes = new TimeStampTokenRes(tsToken.getEncoded(), tsToken.getTimeStampInfo().getGenTime());
        } catch (IOException ex) {
            throw new TimeStampTokenGenerationException("Encoding error", ex);
        }

        return tsTokenRes;
    }

    private TimeStampResponse getTimeStampResponse(TimeStampRequest tsRequest) throws TimeStampTokenGenerationException {
        TimeStampResponse tsResponse;
        try {
            byte[] responseStream = getResponse(tsRequest.getEncoded());
            tsResponse = new TimeStampResponse(responseStream);
        } catch (TSPException ex) {
            throw new TimeStampTokenGenerationException("Invalid time stamp response", ex);
        } catch (IOException ex) {
            throw new TimeStampTokenGenerationException("Encoding error", ex);
        }

        return tsResponse;
    }

    abstract byte[] getResponse(byte[] encodedRequest) throws TimeStampTokenGenerationException;
}
