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

import org.junit.jupiter.api.Test;

import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author Luís
 */
class FileSystemDirectoryCertStoreTest
{
    @Test
    void testGetStoreMy() throws Exception
    {
        FileSystemDirectoryCertStore certStore = new FileSystemDirectoryCertStore("./src/test/cert/my");
        Collection<? extends Certificate> certs = certStore.getStore().getCertificates(null);
        assertEquals(4, certs.size());
    }

    @Test
    void testGetStoreNist() throws Exception
    {
        FileSystemDirectoryCertStore certStore = new FileSystemDirectoryCertStore("./src/test/cert/csrc.nist");
        Collection<? extends Certificate> certs = certStore.getStore().getCertificates(null);
        assertEquals(4, certs.size());
        Collection<? extends CRL> crls = certStore.getStore().getCRLs(null);
        assertEquals(3, crls.size());
    }
}