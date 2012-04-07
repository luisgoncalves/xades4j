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
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import javax.security.auth.x500.X500Principal;
import xades4j.properties.CompleteRevocationRefsProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.UnsupportedAlgorithmException;
import xades4j.properties.data.CRLRef;
import xades4j.properties.data.CompleteRevocationRefsData;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.utils.CrlExtensionsUtils;

/**
 * XAdES G.2.2.13
 * @author Luís
 */
class CompleteRevocRefsVerifier implements QualifyingPropertyVerifier<CompleteRevocationRefsData>
{
    private final MessageDigestEngineProvider digestEngineProvider;

    @Inject
    public CompleteRevocRefsVerifier(
            MessageDigestEngineProvider digestEngineProvider)
    {
        this.digestEngineProvider = digestEngineProvider;
    }

    @Override
    public QualifyingProperty verify(
            CompleteRevocationRefsData propData,
            QualifyingPropertyVerificationContext ctx) throws InvalidPropertyException
    {
        Collection<X509CRL> crls = ctx.getCertChainData().getCrls();
        Collection<CRLRef> crlRefs = new ArrayList<CRLRef>(propData.getCrlRefs());

        if(crls.isEmpty())
            throw new CompleteRevocRefsCRLsNotAvailableException();

        for (X509CRL crl : crls)
        {
            CRLRef match = null;
            for (CRLRef crlRef : crlRefs)
            {
                // "If any of these checks fails, repeat the process for the next
                // CRLRef elements until finding one satisfying them or finishing
                // the list. If none of the references matches the CRL, the verifier
                // should treat the signature as invalid."

                // Check issuer and issue time.
                if (!crl.getIssuerX500Principal().equals(new X500Principal(crlRef.issuerDN)) ||
                        !crl.getThisUpdate().equals(crlRef.issueTime.getTime()))
                    continue;
                
                try
                {
                    // Check CRL number, if present.
                    if (crlRef.serialNumber != null)
                    {
                        BigInteger crlNum = CrlExtensionsUtils.getCrlNumber(crl);
                        if (crlNum != null && !crlRef.serialNumber.equals(crlNum))
                            continue;
                    }

                    // Check digest value.
                    MessageDigest md = this.digestEngineProvider.getEngine(crlRef.digestAlgUri);
                    if (Arrays.equals(md.digest(crl.getEncoded()), crlRef.digestValue))
                    {
                        match = crlRef;
                        break;
                    }
                } 
                catch(IOException ex)
                {
                    throw new CompleteRevocRefsReferenceException(crl, ex.getMessage());
                }
                catch (CRLException ex)
                {
                    throw new CompleteRevocRefsReferenceException(crl, ex.getMessage());
                }
                catch (UnsupportedAlgorithmException ex)
                {
                    throw new CompleteRevocRefsReferenceException(crl, ex.getMessage());
                }
            }

            if (null == match)
                throw new CompleteRevocRefsReferenceException(crl, "no matching reference");

            crlRefs.remove(match);
        }

        return new CompleteRevocationRefsProperty(crls);
    }
}
