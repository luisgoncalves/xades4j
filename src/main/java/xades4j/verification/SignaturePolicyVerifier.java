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
package xades4j.verification;

import com.google.inject.Inject;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import xades4j.properties.ObjectIdentifier;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.SignaturePolicyIdentifierProperty;
import xades4j.properties.SignaturePolicyImpliedProperty;
import xades4j.UnsupportedAlgorithmException;
import xades4j.properties.data.SignaturePolicyData;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.SignaturePolicyDocumentProvider;
import xades4j.utils.StreamUtils;

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
            return new SignaturePolicyImpliedProperty();

        // Get the policy document.
        InputStream sigDocStream = this.policyDocumentProvider.getSignaturePolicyDocumentStream(policyId);
        if (null == sigDocStream)
            throw new SignaturePolicyNotAvailableException(policyId);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try
        {
            StreamUtils.readWrite(sigDocStream, baos);
            sigDocStream.close();
        } catch (IOException ex)
        {
            throw new SignaturePolicyNotAvailableException(policyId);
        }
        byte[] sigDocBytes = baos.toByteArray();

        // Check the document digest.
        try
        {
            MessageDigest md = this.messageDigestProvider.getEngine(propData.getDigestAlgorithm());
            if (!Arrays.equals(md.digest(sigDocBytes), propData.getDigestValue()))
                throw new SignaturePolicyDigestMismatchException(policyId);
            return new SignaturePolicyIdentifierProperty(policyId, sigDocStream);
        } catch (UnsupportedAlgorithmException ex)
        {
            throw new SignaturePolicyCannotDigestException(policyId, ex.getMessage());
        }
    }
}
