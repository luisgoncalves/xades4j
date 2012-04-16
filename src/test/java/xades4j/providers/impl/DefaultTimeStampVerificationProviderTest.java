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
        doVerifyToken(tsDigestInput);
    }

    @Test(expected = TimeStampTokenDigestException.class)
    public void testVerifyTokenFailsWithDifferentDigestInput() throws Exception
    {
        System.out.println("terifyTokenFailsWithDifferentDigestInput");

        byte[] tsDigestInput = "Invalid".getBytes();
        doVerifyToken(tsDigestInput);
    }

    public void doVerifyToken(byte[] tsDigestInput) throws Exception
    {
        // The 'tstoken' file contains an encoded time stamp token issued by
        // http://tss.accv.es:8318/tsa. The input was "TestDigestInput"
        String tokenPath = "./src/test/java/" + this.getClass().getPackage().getName().replace('.', '/') + "/tstoken";
        FileInputStream is = new FileInputStream(tokenPath);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        StreamUtils.readWrite(is, bos);
        is.close();

        byte[] tsToken = bos.toByteArray();

        KeyStore ks = createAndLoadJKSKeyStore("gva/trustAnchor", "password");
        PKIXCertificateValidationProvider certificateValidationProvider = new PKIXCertificateValidationProvider(ks, false);

        DefaultTimeStampVerificationProvider timeStampVerificationProvider = new DefaultTimeStampVerificationProvider(
                certificateValidationProvider,
                new DefaultMessageDigestProvider());

        timeStampVerificationProvider.verifyToken(tsToken, tsDigestInput);
    }
}
