/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Hubert Kario - QBS.
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

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

import com.google.inject.Inject;

import xades4j.UnsupportedAlgorithmException;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.TimeStampTokenGenerationException;
import xades4j.providers.TimeStampTokenProvider;

/**
 * TimeStampTokenProvider that uses its own internal time source and generator
 * @author Hubert Kario
 *
 */
// only package visible, users shouldn't use this class
class SurrogateTimeStampTokenProvider implements TimeStampTokenProvider
{
    private static FullCert tsaCert;
    private static String algorithm = "SHA1withRSA";
    private static Date now = null;
    private static BigInteger serial;

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

    private MessageDigestEngineProvider mdEngineProvider;

    /**
     * change time stamp token signature algorithm from default SHA1withRSA
     * @param alg
     */
    public static void setSigAlgorithm(String alg)
    {
        algorithm = alg;
    }

    public static void setTSACert(FullCert cert)
    {
        tsaCert = cert;
    }

    public static void setTimeAndSerial(Date time, BigInteger serial)
    {
        now = time;
        SurrogateTimeStampTokenProvider.serial = serial;
    }

    @Inject
    public SurrogateTimeStampTokenProvider(MessageDigestEngineProvider messageDigest)
    {
        mdEngineProvider = messageDigest;
    }

    @Override
    public TimeStampTokenRes getTimeStampToken(byte[] tsDigestInput,
            String digestAlgUri) throws TimeStampTokenGenerationException
    {
        if (now == null)
            throw new IllegalStateException("Double use or not initialised");

        try
        {
            // calculate digest of data
            MessageDigest md = mdEngineProvider.getEngine(digestAlgUri);
            byte[] digest = md.digest(tsDigestInput);

            // create time stamp token generator
            TimeStampTokenGenerator tokenGenerator;
            DigestCalculator sha1DigestCalculator = new DigestCalculator()
            {
                /* SHA1 is hardcoded in few places in the library itself so hardcoding it
                 * ourselves we don't make the situation as bad as it looks
                 */
                private ByteArrayOutputStream bOut = new ByteArrayOutputStream();

                public AlgorithmIdentifier getAlgorithmIdentifier()
                {
                    return new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);
                }

                public OutputStream getOutputStream()
                {
                    return bOut;
                }

                public byte[] getDigest()
                {
                    try
                    {
                        return MessageDigest.getInstance("SHA-1").digest(bOut.toByteArray());
                    }
                    catch (NoSuchAlgorithmException e)
                    {
                        throw new IllegalStateException("Cannot create sha-1 hash: "+ e.getMessage());
                    }
                }
            };
            /* because Bouncy Castle adds *two* timestamps to a token (one from system
             * time, in attributes of CMS signature, and one from Date passed to
             * generate() method we have to override the first one.
             *
             * Otherwise we could simply run
             *
             * SignerInfoGenerator signerInfoGen = new JcaSimpleSignerInfoGeneratorBuilder()
             *       .build(algorithm, tsaCert.getPrivateKey(), tsaCert.getCertificate());
             */
            JcaSignerInfoGeneratorBuilder sigBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());

            // create default signingTime CMS attribute to be added to
            // signedAttributes
            // in CMS (RFC 3161 token) signature
            Hashtable<ASN1ObjectIdentifier, Attribute> signedAttr =
                   new Hashtable<ASN1ObjectIdentifier, Attribute>();
            Attribute attr = new Attribute(CMSAttributes.signingTime,
                   new DERSet(new Time(now)));
            signedAttr.put(attr.getAttrType(), attr);
            AttributeTable signedAttributeTable = new AttributeTable(signedAttr);

            sigBuilder.setSignedAttributeGenerator(
                   new DefaultSignedAttributeTableGenerator(signedAttributeTable));

            SignerInfoGenerator signerInfoGen = sigBuilder.build(
                   new JcaContentSignerBuilder(algorithm).setProvider("BC")
                   .build(tsaCert.getPrivateKey()), tsaCert
                   .getCertificate());

            // "1.2" is a "no policy" policy ID
            tokenGenerator = new TimeStampTokenGenerator(sha1DigestCalculator,
                    signerInfoGen,new ASN1ObjectIdentifier("1.2"));

            //tokenGenerator.addCertificates(caCerts);

            // generate signing request
            TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
            TimeStampRequest request = reqGen.generate(digestUriToOidMappings.get(digestAlgUri), digest);

            // create response signer
            TimeStampResponseGenerator tsrg = new TimeStampResponseGenerator(tokenGenerator,
                    TSPAlgorithms.ALLOWED);

            // sign request
            TimeStampResponse resp = tsrg.generate(request, serial, now);

            // extract token from response
            TimeStampToken tsToken = resp.getTimeStampToken();

            now = null; // reset, so that every use needs to set time it wants to see

            return new TimeStampTokenRes(tsToken.getEncoded(),
                    tsToken.getTimeStampInfo().getGenTime());

        } catch (UnsupportedAlgorithmException e)
        {
            throw new TimeStampTokenGenerationException("Digest algorithm not supported", e);
        } catch (Exception e)
        {
            throw new TimeStampTokenGenerationException("Something went wrong", e);
        }
    }
}
