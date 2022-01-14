/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Luis Goncalves.
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

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import org.junit.Test;
import xades4j.providers.TimeStampTokenDigestException;
import xades4j.providers.TimeStampTokenVerificationException;
import xades4j.utils.StreamUtils;
import xades4j.verification.VerifierTestBase;

/**
 *
 * @author Luís
 */
public class DefaultTimeStampVerificationProviderTest extends VerifierTestBase
{
    @Test
    public void testVerifyTokenSucceeds() throws Exception
    {
        System.out.println("verifyTokenSucceeds");

        byte[] tsDigestInput = "TestDigestInput".getBytes();
        doVerifyToken(tsDigestInput, getTestToken());
    }

    @Test(expected = TimeStampTokenDigestException.class)
    public void testVerifyTokenFailsWithDifferentDigestInput() throws Exception
    {
        System.out.println("terifyTokenFailsWithDifferentDigestInput");

        byte[] tsDigestInput = "Invalid".getBytes();
        doVerifyToken(tsDigestInput, getTestToken());
    }

    @Test(expected = TimeStampTokenVerificationException.class)
    public void testVerifyTokenFailsWithTamperedToken() throws Exception
    {
        System.out.println("verifyTokenFailsWithTamperedToken");

        byte[] tsDigestInput = "TestDigestInput".getBytes();
        byte[] tsToken = getTestToken();

        for (int i = 0; i < tsToken.length; i++)
        {
            if(i % 10 == 1){
                tsToken[i] = tsToken[i-1];
            }
        }

        doVerifyToken(tsDigestInput, tsToken);
    }

    private byte[] getTestToken() throws Exception
    {
        // The 'tstoken' file contains an encoded time stamp token issued by
        // http://tss.accv.es:8318/tsa. The input was "TestDigestInput"
        String tokenPath = "./src/test/java/" + this.getClass().getPackage().getName().replace('.', '/') + "/tstoken";
        FileInputStream is = new FileInputStream(tokenPath);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        StreamUtils.readWrite(is, bos);
        is.close();

        return bos.toByteArray();
    }

    private void doVerifyToken(byte[] tsDigestInput, byte[] tsToken) throws Exception
    {
        KeyStore ks = createAndLoadJKSKeyStore("gva/trustAnchor", "password");
        PKIXCertificateValidationProvider certificateValidationProvider = PKIXCertificateValidationProvider
                .builder(ks)
                .checkRevocation(false)
                .build();

        DefaultTimeStampVerificationProvider timeStampVerificationProvider = new DefaultTimeStampVerificationProvider(
                certificateValidationProvider,
                new DefaultMessageDigestProvider());

        timeStampVerificationProvider.verifyToken(tsToken, tsDigestInput);
    }
}
