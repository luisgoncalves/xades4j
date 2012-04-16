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
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampToken;
import xades4j.UnsupportedAlgorithmException;
import xades4j.XAdES4jException;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.TimeStampTokenDigestException;
import xades4j.providers.TimeStampTokenSignatureException;
import xades4j.providers.TimeStampTokenStructureException;
import xades4j.providers.TimeStampTokenTSACertException;
import xades4j.providers.TimeStampTokenVerificationException;
import xades4j.providers.TimeStampVerificationProvider;
import xades4j.providers.ValidationData;

/**
 * Default implementation of {@code TimeStampVerificationProvider}. It verifies
 * the token signature, including the TSA certificate, and the digest imprint.
 * <p>
 * The implementation is based on Bouncy Castle and <b>only supports DER-encoded tokens</b>.
 * @author Luís
 */
public class DefaultTimeStampVerificationProvider implements TimeStampVerificationProvider
{

    private static final Map<ASN1ObjectIdentifier, String> digestOidToUriMappings;

    static
    {
        digestOidToUriMappings = new HashMap<ASN1ObjectIdentifier, String>(5);
        digestOidToUriMappings.put(TSPAlgorithms.MD5, MessageDigestAlgorithm.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5);
        digestOidToUriMappings.put(TSPAlgorithms.RIPEMD160, MessageDigestAlgorithm.ALGO_ID_DIGEST_RIPEMD160);
        digestOidToUriMappings.put(TSPAlgorithms.SHA1, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1);
        digestOidToUriMappings.put(TSPAlgorithms.SHA256, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
        digestOidToUriMappings.put(TSPAlgorithms.SHA384, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384);
        digestOidToUriMappings.put(TSPAlgorithms.SHA512, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512);
    }

    // TODO this probably should be a provider to avoid being dependent on a fixed set of algorithms
    private static String uriForDigest(ASN1ObjectIdentifier digestalgOid)
    {
        return digestOidToUriMappings.get(digestalgOid);
    }
    private final CertificateValidationProvider certificateValidationProvider;
    private final MessageDigestEngineProvider messageDigestProvider;
    private final JcaSimpleSignerInfoVerifierBuilder signerInfoVerifierBuilder;
    private final JcaX509CertificateConverter x509CertificateConverter;
    private final JcaX509CertSelectorConverter x509CertSelectorConverter;

    @Inject
    public DefaultTimeStampVerificationProvider(
            CertificateValidationProvider certificateValidationProvider,
            MessageDigestEngineProvider messageDigestProvider)
    {
        this.certificateValidationProvider = certificateValidationProvider;
        this.messageDigestProvider = messageDigestProvider;

        Provider bcProv = new BouncyCastleProvider();
        this.signerInfoVerifierBuilder = new JcaSimpleSignerInfoVerifierBuilder().setProvider(bcProv);
        this.x509CertificateConverter = new JcaX509CertificateConverter().setProvider(bcProv);
        this.x509CertSelectorConverter = new JcaX509CertSelectorConverter();
    }

    @Override
    public Date verifyToken(byte[] timeStampToken, byte[] tsDigestInput) throws TimeStampTokenVerificationException
    {
        TimeStampToken tsToken;
        try
        {
            ContentInfo tsContentInfo = ContentInfo.getInstance(new ASN1InputStream(timeStampToken).readObject());
            tsToken = new TimeStampToken(tsContentInfo);
        } catch (IOException ex)
        {
            throw new TimeStampTokenStructureException("Error parsing encoded token", ex);
        } catch (TSPException ex)
        {
            throw new TimeStampTokenStructureException("Invalid token", ex);
        }

        X509Certificate tsaCert = null;
        try
        {
            /* Validate the TSA certificate */

            // TODO should extract all certificates from the token
            Iterator certsIt = tsToken.getCertificates().getMatches(tsToken.getSID()).iterator();
            if (certsIt.hasNext())
            {
                tsaCert = this.x509CertificateConverter.getCertificate((X509CertificateHolder) certsIt.next());
            }

            ValidationData vData = this.certificateValidationProvider.validate(
                    x509CertSelectorConverter.getCertSelector(tsToken.getSID()),
                    tsToken.getTimeStampInfo().getGenTime(),
                    null == tsaCert ? null : Collections.singletonList(tsaCert));

            tsaCert = vData.getCerts().get(0);
        }
        catch (CertificateException ex)
        {
            throw new TimeStampTokenVerificationException(ex.getMessage(), ex);
        }
        catch (XAdES4jException ex)
        {
            throw new TimeStampTokenTSACertException("cannot validate TSA certificate", ex);
        }

        try
        {
            tsToken.validate(this.signerInfoVerifierBuilder.build(tsaCert));
        }
        catch (TSPValidationException ex)
        {
            throw new TimeStampTokenSignatureException("Invalid token signature or certificate", ex);
        }
        catch (Exception ex)
        {
            throw new TimeStampTokenVerificationException("Error when verifying the token signature", ex);
        }

        org.bouncycastle.tsp.TimeStampTokenInfo tsTokenInfo = tsToken.getTimeStampInfo();

        try
        {
            String digestAlgUri = uriForDigest(tsTokenInfo.getMessageImprintAlgOID());
            MessageDigest md = messageDigestProvider.getEngine(digestAlgUri);

            if (!Arrays.equals(md.digest(tsDigestInput), tsTokenInfo.getMessageImprintDigest()))
            {
                throw new TimeStampTokenDigestException();
            }
        }
        catch (UnsupportedAlgorithmException ex)
        {
            throw new TimeStampTokenVerificationException("The token's digest algorithm is not supported", ex);
        }

        return tsTokenInfo.getGenTime();
    }
}
