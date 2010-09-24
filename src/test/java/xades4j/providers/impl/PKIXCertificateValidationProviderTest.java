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

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import javax.security.auth.x500.X500Principal;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import xades4j.providers.ValidationData;
import xades4j.utils.FileSystemDirectoryCertStore;

/**
 *
 * @author Luís
 */
public class PKIXCertificateValidationProviderTest
{
    public PKIXCertificateValidationProviderTest()
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

    @Test
    public void testValidateMy() throws Exception
    {
        System.out.println("validateMy");

        FileSystemDirectoryCertStore certStore = new FileSystemDirectoryCertStore(".\\src\\test\\cert\\my");
        KeyStore ks = KeyStore.getInstance("jks");
        FileInputStream fis = new FileInputStream(".\\src\\test\\cert\\my\\myStore");
        ks.load(fis, "mystorepass".toCharArray());
        fis.close();

        X509CertSelector certSelector = new X509CertSelector();
        certSelector.setSubject(new X500Principal("CN = Luis Goncalves,OU = CC,O = ISEL,C = PT"));
        Collection<X509Certificate> otherCerts = Collections.emptyList();

        PKIXCertificateValidationProvider instance = new PKIXCertificateValidationProvider(ks, false, certStore.getStore());
        ValidationData result = instance.validate(certSelector, otherCerts);
        assertEquals(result.getCerts().size(), 3);
    }

    @Test
    public void testValidateNist() throws Exception
    {
        System.out.println("validateNist");

        FileSystemDirectoryCertStore certStore = new FileSystemDirectoryCertStore(".\\src\\test\\cert\\csrc.nist");
        KeyStore ks = KeyStore.getInstance("jks");
        FileInputStream fis = new FileInputStream(".\\src\\test\\cert\\csrc.nist\\trustAnchor");
        ks.load(fis, "password".toCharArray());
        fis.close();

        X509CertSelector certSelector = new X509CertSelector();
        certSelector.setSubject(new X500Principal("CN = User1-CP.02.01,OU = Testing,OU = DoD,O = U.S. Government,C = US"));
        Collection<X509Certificate> otherCerts = Collections.emptyList();

        PKIXCertificateValidationProvider instance = new PKIXCertificateValidationProvider(ks, true, certStore.getStore());
        ValidationData result = instance.validate(certSelector, otherCerts);
        assertEquals(result.getCerts().size(), 4);
        assertEquals(result.getCrls().size(), 3);
    }
}
