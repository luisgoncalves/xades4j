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
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.GregorianCalendar;
import xades4j.properties.CompleteRevocationRefsProperty;
import xades4j.UnsupportedAlgorithmException;
import xades4j.properties.data.CRLRef;
import xades4j.properties.data.CompleteRevocationRefsData;
import xades4j.properties.data.PropertyDataObject;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.utils.CrlExtensionsUtils;

/**
 *
 * @author Luís
 */
class DataGenCompleteRevocRefs implements PropertyDataObjectGenerator<CompleteRevocationRefsProperty>
{
    private final MessageDigestEngineProvider messageDigestProvider;
    private final AlgorithmsProviderEx algorithmsProvider;

    @Inject
    public DataGenCompleteRevocRefs(
            MessageDigestEngineProvider messageDigestProvider,
            AlgorithmsProviderEx algorithmsProvider)
    {
        this.messageDigestProvider = messageDigestProvider;
        this.algorithmsProvider = algorithmsProvider;
    }

    @Override
    public PropertyDataObject generatePropertyData(
            CompleteRevocationRefsProperty prop,
            PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException
    {
        Collection<X509CRL> crls = prop.getCrls();
        Collection<CRLRef> crlRefs = new ArrayList<CRLRef>(crls.size());
        String digestAlgUri = this.algorithmsProvider.getDigestAlgorithmForReferenceProperties();

        try
        {
            MessageDigest messageDigest = this.messageDigestProvider.getEngine(digestAlgUri);
            for (X509CRL crl : crls)
            {
                GregorianCalendar crlTime = new GregorianCalendar();
                crlTime.setTime(crl.getThisUpdate());
                byte[] digest = messageDigest.digest(crl.getEncoded());
                BigInteger crlNum = CrlExtensionsUtils.getCrlNumber(crl);
               
                crlRefs.add(new CRLRef(
                        crl.getIssuerX500Principal().getName(),
                        crlNum,
                        digestAlgUri,
                        digest,
                        crlTime));
            }

            return new CompleteRevocationRefsData(crlRefs);
        }
        catch (CRLException ex)
        {
            throw new PropertyDataGenerationException(prop, "cannot get encoded CRL", ex);
        }
        catch(IOException ex)
        {
            throw new PropertyDataGenerationException(prop, "cannot parse CRL number extension", ex);
        }
        catch (UnsupportedAlgorithmException ex)
        {
            throw new PropertyDataGenerationException(prop, ex.getMessage(), ex);
        }
    }
}
