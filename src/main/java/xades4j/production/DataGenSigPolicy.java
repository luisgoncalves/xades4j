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
package xades4j.production;

import com.google.inject.Inject;
import java.io.IOException;
import java.security.MessageDigest;
import xades4j.properties.SignaturePolicyIdentifierProperty;
import xades4j.UnsupportedAlgorithmException;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.SignaturePolicyData;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.utils.MessageDigestUtils;

/**
 *
 * @author Luís
 */
class DataGenSigPolicy implements PropertyDataObjectGenerator<SignaturePolicyIdentifierProperty>
{
    private final MessageDigestEngineProvider messageDigestProvider;
    private final AlgorithmsProviderEx algorithmsProvider;

    @Inject
    public DataGenSigPolicy(
            MessageDigestEngineProvider messageDigestProvider,
            AlgorithmsProviderEx algorithmsProvider)
    {
        this.messageDigestProvider = messageDigestProvider;
        this.algorithmsProvider = algorithmsProvider;
    }

    @Override
    public PropertyDataObject generatePropertyData(
            SignaturePolicyIdentifierProperty prop,
            PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException
    {
        try
        {
            // Digest the policy document.
            String digestAlgUri = this.algorithmsProvider.getDigestAlgorithmForReferenceProperties();
            MessageDigest md = this.messageDigestProvider.getEngine(digestAlgUri);
            byte[] policyDigest = MessageDigestUtils.digestStream(md, prop.getPolicyDocumentStream());

            return new SignaturePolicyData(
                    prop.getIdentifier(),
                    digestAlgUri,
                    policyDigest,
                    prop.getLocationUrl());

        } catch (IOException ex)
        {
            throw new PropertyDataGenerationException(prop, "Cannot digest signature policy", ex);
        } catch (UnsupportedAlgorithmException ex)
        {
            throw new PropertyDataGenerationException(prop, ex.getMessage(), ex);
        }
    }
}
