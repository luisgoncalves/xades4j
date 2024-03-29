/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2017 Luis Goncalves.
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

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.junit.jupiter.api.Test;
import xades4j.providers.TimeStampTokenProvider.TimeStampTokenRes;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class HttpTimeStampTokenProviderTest
{
    @Test
    void testGetTimeStampToken() throws Exception
    {
        byte[] tsDigestInput = "TestDigestInput".getBytes();
        String digestAlgUri = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1;

        HttpTimeStampTokenProvider instance = new HttpTimeStampTokenProvider(
                new DefaultMessageDigestProvider(),
                new HttpTsaConfiguration("http://tss.accv.es:8318/tsa"));

        TimeStampTokenRes result = instance.getTimeStampToken(tsDigestInput, digestAlgUri);

        assertNotNull(result);
        assertNotNull(result.encodedTimeStampToken);
        assertNotNull(result.timeStampTime);
    }
}
