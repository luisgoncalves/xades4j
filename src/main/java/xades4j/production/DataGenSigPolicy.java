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
package xades4j.production;

import com.google.inject.Inject;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import xades4j.properties.SignaturePolicyIdentifierProperty;
import xades4j.UnsupportedAlgorithmException;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.SignaturePolicyData;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.utils.StreamUtils;

/**
 *
 * @author Luís
 */
class DataGenSigPolicy implements PropertyDataObjectGenerator<SignaturePolicyIdentifierProperty>
{
    private final MessageDigestEngineProvider messageDigestProvider;

    @Inject
    public DataGenSigPolicy(MessageDigestEngineProvider messageDigestProvider)
    {
        this.messageDigestProvider = messageDigestProvider;
    }

    @Override
    public PropertyDataObject generatePropertyData(
            SignaturePolicyIdentifierProperty prop,
            PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException
    {
        try
        {
            // Get the policy document data.
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            StreamUtils.readWrite(prop.getPolicyDocumentStream(), baos);
            // Digest the policy document.
            String digestAlgUri = ctx.getAlgorithmsProvider().getDigestAlgorithmForReferenceProperties();
            byte[] policyDigest = messageDigestProvider.getEngine(digestAlgUri).digest(baos.toByteArray());

            return new SignaturePolicyData(
                    prop.getIdentifier(),
                    digestAlgUri,
                    policyDigest);

        } catch (IOException ex)
        {
            throw new PropertyDataGenerationException("Cannot digest signature policy: " + ex.getMessage(), prop);
        } catch (UnsupportedAlgorithmException ex)
        {
            throw new PropertyDataGenerationException(ex.getMessage(), prop);
        }
    }
}
