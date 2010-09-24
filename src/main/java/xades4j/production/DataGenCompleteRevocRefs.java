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
import xades4j.providers.MessageDigestEngineProvider;

/**
 *
 * @author Luís
 */
class DataGenCompleteRevocRefs implements PropertyDataObjectGenerator<CompleteRevocationRefsProperty>
{
    private final MessageDigestEngineProvider messageDigestProvider;

    @Inject
    public DataGenCompleteRevocRefs(
            MessageDigestEngineProvider messageDigestProvider)
    {
        this.messageDigestProvider = messageDigestProvider;
    }

    @Override
    public PropertyDataObject generatePropertyData(
            CompleteRevocationRefsProperty prop,
            PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException
    {
        Collection<X509CRL> crls = prop.getCrls();
        Collection<CRLRef> crlRefs = new ArrayList<CRLRef>(crls.size());
        String digestAlgUri = ctx.getAlgorithmsProvider().getDigestAlgorithmForReferenceProperties();

        try
        {
            MessageDigest messageDigest = messageDigestProvider.getEngine(digestAlgUri);
            for (X509CRL crl : crls)
            {
                GregorianCalendar crlTime = new GregorianCalendar();
                crlTime.setTime(crl.getThisUpdate());

                byte[] digest = messageDigest.digest(crl.getEncoded());

                byte[] crlNumEnc = crl.getExtensionValue("2.5.29.20");
                BigInteger crlNum = null;
                if (crlNumEnc != null)
                    crlNum = new BigInteger(crlNumEnc);

                crlRefs.add(new CRLRef(
                        crl.getIssuerX500Principal().getName(),
                        crlNum,
                        digestAlgUri,
                        digest,
                        crlTime));
            }

            return new CompleteRevocationRefsData(crlRefs);
        } catch (CRLException ex)
        {
            throw new PropertyDataGenerationException("Cannot encode CRL to be digested", prop);
        } catch (UnsupportedAlgorithmException ex)
        {
            throw new PropertyDataGenerationException(ex.getMessage(), prop);
        }
    }
}
