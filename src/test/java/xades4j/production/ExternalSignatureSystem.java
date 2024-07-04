/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2024 Luis Goncalves.
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

package xades4j.production;

import xades4j.providers.CertificateValidationProvider;
import xades4j.verification.VerifierTestBase;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

/**
 * A fictitious external system that performs signature operations.
 * <p>
 * The {@link #sign(ByteBuffer, String)} method is the entrypoint and could be implemented in any way.
 * The example implementation uses the existing test key material and JCA.
 */
final class ExternalSignatureSystem
{
    private static final X509Certificate _certificate;
    private static final PrivateKey _key;

    static
    {
        try
        {
            _certificate = SignerTestBase.keyingProviderMy.getSigningCertificateChain().get(0);
            _key = SignerTestBase.keyingProviderMy.getSigningKey(_certificate);
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate getSigningCertificate() throws Exception
    {
        return _certificate;

    }

    public static CertificateValidationProvider getCertificateValidationProvider()
    {
        return VerifierTestBase.validationProviderMySigs;
    }

    public static byte[] sign(ByteBuffer content, String algorithm) throws SignatureException
    {
        try
        {
            Signature s = Signature.getInstance(algorithm);
            s.initSign(_key);
            s.update(content);
            return s.sign();
        }
        catch (Exception e)
        {
            throw new SignatureException(e);
        }
    }
}
