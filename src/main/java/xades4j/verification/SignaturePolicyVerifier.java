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

import com.google.inject.Inject;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;

import org.w3c.dom.Element;

import xades4j.properties.ObjectIdentifier;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.SignaturePolicyIdentifierProperty;
import xades4j.properties.SignaturePolicyImpliedProperty;
import xades4j.UnsupportedAlgorithmException;
import xades4j.properties.data.SignaturePolicyData;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.SignaturePolicyDocumentProvider;
import xades4j.utils.MessageDigestUtils;

/**
 *
 * @author Luís
 */
class SignaturePolicyVerifier implements QualifyingPropertyVerifier<SignaturePolicyData>
{

    private final SignaturePolicyDocumentProvider policyDocumentProvider;
    private final MessageDigestEngineProvider messageDigestProvider;

    @Inject
    public SignaturePolicyVerifier(
            SignaturePolicyDocumentProvider policyDocumentProvider,
            MessageDigestEngineProvider messageDigestProvider)
    {
        this.policyDocumentProvider = policyDocumentProvider;
        this.messageDigestProvider = messageDigestProvider;
    }

    @Override
    public QualifyingProperty verify(
            SignaturePolicyData propData,
            QualifyingPropertyVerificationContext ctx) throws SignaturePolicyVerificationException
    {
        ObjectIdentifier policyId = propData.getIdentifier();
        if (null == policyId)
        {
            return new SignaturePolicyImpliedProperty();
        }

        // Get the policy document
        InputStream sigDocStream = this.policyDocumentProvider.getSignaturePolicyDocumentStream(policyId);
        if (null == sigDocStream)
        {
            throw new SignaturePolicyNotAvailableException(policyId, null);
        }

        try
        {
            MessageDigest md = this.messageDigestProvider.getEngine(propData.getDigestAlgorithm());
            byte[] sigDocDigest = MessageDigestUtils.digestStream(md, sigDocStream);

            // Check the document digest.
            if (!Arrays.equals(sigDocDigest, propData.getDigestValue()))
            {
                throw new SignaturePolicyDigestMismatchException(policyId);
            }

            return new SignaturePolicyIdentifierProperty(policyId, sigDocStream)
                    .withLocationUrl(propData.getLocationUrl());
        } catch (IOException ex)
        {
            throw new SignaturePolicyNotAvailableException(policyId, ex);
        } catch (UnsupportedAlgorithmException ex)
        {
            throw new SignaturePolicyCannotDigestException(policyId, ex);
        } finally
        {
            try
            {
                sigDocStream.close();
            } catch (IOException ex)
            {
                throw new SignaturePolicyNotAvailableException(policyId, ex);
            }
        }
    }

    @Override
    public QualifyingProperty verify(SignaturePolicyData propData,
            Element elem, QualifyingPropertyVerificationContext ctx)
            throws InvalidPropertyException
    {
        return verify(propData, ctx);
    }
}
