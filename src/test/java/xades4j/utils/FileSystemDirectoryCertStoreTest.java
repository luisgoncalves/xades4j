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
package xades4j.utils;

import java.util.Collection;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Luís
 */
public class FileSystemDirectoryCertStoreTest {

    public FileSystemDirectoryCertStoreTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception
    {
    }

    @AfterClass
    public static void tearDownClass() throws Exception
    {
    }

    @Test
    public void testGetStoreMy() throws Exception
    {
        FileSystemDirectoryCertStore certStore = new FileSystemDirectoryCertStore("./src/test/cert/my");
        Collection certs = certStore.getStore().getCertificates(null);
        assertEquals(certs.size(), 4);
    }
    @Test
    public void testGetStoreNist() throws Exception
    {
        FileSystemDirectoryCertStore certStore = new FileSystemDirectoryCertStore("./src/test/cert/csrc.nist");
        Collection certs = certStore.getStore().getCertificates(null);
        assertEquals(certs.size(), 4);
        Collection crls = certStore.getStore().getCRLs(null);
        assertEquals(crls.size(), 3);
    }
}