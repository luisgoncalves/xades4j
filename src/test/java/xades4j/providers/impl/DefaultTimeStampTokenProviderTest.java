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
package xades4j.providers.impl;

import xades4j.providers.impl.DefaultMessageDigestProvider;
import xades4j.providers.impl.DefaultTimeStampTokenProvider;
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
