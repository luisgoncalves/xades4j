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
package xades4j.providers.impl;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.junit.Test;
import static org.junit.Assert.*;
import xades4j.providers.TimeStampTokenProvider.TimeStampTokenRes;

/**
 *
 * @author Luís
 */
public class DefaultTimeStampTokenProviderTest
{
    @Test
    public void testGetTimeStampToken() throws Exception
    {
        System.out.println("getTimeStampToken");
        byte[] tsDigestInput = "TestDigestInput".getBytes();
        String digestAlgUri = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1;

        DefaultTimeStampTokenProvider instance = new DefaultTimeStampTokenProvider(new DefaultMessageDigestProvider());

        TimeStampTokenRes result = instance.getTimeStampToken(tsDigestInput, digestAlgUri);

        assertNotNull(result);
        assertNotNull(result.encodedTimeStampToken);
        //updateTestToken(result.encodedTimeStampToken);
        assertNotNull(result.timeStampTime);
        System.out.println(result.timeStampTime);
    }

    private void updateTestToken(byte[] encodedTimeStampToken) throws FileNotFoundException, IOException {
        String tokenPath = "./src/test/java/" + this.getClass().getPackage().getName().replace('.', '/') + "/tstoken";
        File file = new File(tokenPath);
        FileOutputStream is = new FileOutputStream(file);
        try {
            is.write(encodedTimeStampToken);
        } finally {
            is.close();
        }

    }
}
