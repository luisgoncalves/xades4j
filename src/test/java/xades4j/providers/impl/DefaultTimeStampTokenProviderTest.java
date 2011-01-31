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

import org.apache.xml.security.utils.Constants;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import xades4j.providers.TimeStampTokenProvider.TimeStampTokenRes;

/**
 *
 * @author Luís
 */
public class DefaultTimeStampTokenProviderTest
{
    public DefaultTimeStampTokenProviderTest()
    {
    }

    @BeforeClass
    public static void setUpClass() throws Exception
    {
    }

    @AfterClass
    public static void tearDownClass() throws Exception
    {
    }

    @Before
    public void setUp()
    {
    }

    @After
    public void tearDown()
    {
    }

    @Test
    public void testGetTimeStampToken() throws Exception
    {
        System.out.println("getTimeStampToken");
        byte[] tsDigestInput = "TestDigestInput".getBytes();
        String digestAlgUri = Constants.ALGO_ID_DIGEST_SHA1;

        DefaultTimeStampTokenProvider instance = new DefaultTimeStampTokenProvider(new DefaultMessageDigestProvider());
        TimeStampTokenRes result = instance.getTimeStampToken(tsDigestInput, digestAlgUri);

        System.out.println(result.timeStampTime);

    }
}
