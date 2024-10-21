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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import xades4j.providers.ValidationData;
import xades4j.utils.FileSystemDirectoryCertStore;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author Luís
 */
class PKIXCertificateValidationProviderTest
{
    @ParameterizedTest
    @MethodSource
    void testValidateMy(Provider provider) throws Exception
    {
        FileSystemDirectoryCertStore certStore = new FileSystemDirectoryCertStore("./src/test/cert/my");
        KeyStore ks = KeyStore.getInstance("jks");
        FileInputStream fis = new FileInputStream("./src/test/cert/my/myStore");
        ks.load(fis, "mystorepass".toCharArray());
        fis.close();

        X509CertSelector certSelector = new X509CertSelector();
        certSelector.setSubject(new X500Principal("CN = Luis Goncalves,OU = CC,O = ISEL,C = PT"));
        Collection<X509Certificate> otherCerts = Collections.emptyList();

        PKIXCertificateValidationProvider.Builder builder = PKIXCertificateValidationProvider
                .builder(ks)
                .checkRevocation(false)
                .intermediateCertStores(certStore.getStore());

        if (provider != null)
        {
            builder.signatureProvider(provider.getName());
        }

        PKIXCertificateValidationProvider instance = builder.build();

        if (provider != null)
        {
            Security.addProvider(provider);
        }

        ValidationData result = instance.validate(certSelector, new Date(), otherCerts);
        assertEquals(3, result.getCerts().size());

        if (provider != null)
        {
            Security.removeProvider(provider.getName());
        }
    }

    public static Provider[] testValidateMy()
    {
        return new Provider[]{
                null,
                new BouncyCastleProvider()
        };
    }

    @Test
    void testValidateNist() throws Exception
    {
        FileSystemDirectoryCertStore certStore = new FileSystemDirectoryCertStore("./src/test/cert/csrc.nist");
        KeyStore ks = KeyStore.getInstance("jks");
        FileInputStream fis = new FileInputStream("./src/test/cert/csrc.nist/trustAnchor");
        ks.load(fis, "password".toCharArray());
        fis.close();

        X509CertSelector certSelector = new X509CertSelector();
        certSelector.setSubject(new X500Principal("CN = User1-CP.02.01,OU = Testing,OU = DoD,O = U.S. Government,C = US"));
        Collection<X509Certificate> otherCerts = Collections.emptyList();

        PKIXCertificateValidationProvider instance = PKIXCertificateValidationProvider
                .builder(ks)
                .checkRevocation(true)
                .intermediateCertStores(certStore.getStore())
                .build();
        ValidationData result = instance.validate(certSelector, new Date(), otherCerts);
        assertEquals(4, result.getCerts().size());
        assertEquals(3, result.getCrls().size());
    }
}
