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

import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.DirectKeyingDataProvider;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.util.Set;

/**
 * Provider that delegates signature operations to a fictitious {@link ExternalSignatureSystem}.
 *
 * @see <a href="https://docs.oracle.com/en/java/javase/11/security/howtoimplaprovider.html">How to Implement a Provider</a>
 */
final class ExternalSignatureSystemProvider extends Provider
{
    private static final Set<String> _supportedSignatureAlgorithms = Set.of(
            "SHA256withRSA"
    );

    public ExternalSignatureSystemProvider()
    {
        super(ExternalSignatureSystemProvider.class.getSimpleName(), "1.0", "");
        _supportedSignatureAlgorithms.forEach(alg -> {
            putService(new SignatureService(this, alg));
        });
    }

    public KeyingDataProvider getKeyingDataProvider() throws Exception
    {
        return new DirectKeyingDataProvider(
                // The signing certificate to be added to the signature is whatever is used by the external system
                ExternalSignatureSystem.getSigningCertificate(),
                // The signing key is just an handler/marker that this provider can handle. The key instance could have
                // some parameters to control the behavior of the external system (e.g. a key ID).
                new MarkerPrivateKey());
    }

    private static final class SignatureService extends Provider.Service
    {
        public SignatureService(Provider provider, String algorithm)
        {
            super(provider, "Signature", algorithm, SignatureAdapter.class.getName(), null, null);
        }

        @Override
        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException
        {
            return new SignatureAdapter(getAlgorithm());
        }
    }

    private static final class MarkerPrivateKey implements PrivateKey
    {
        @Override
        public String getAlgorithm()
        {
            return "RSA";
        }

        @Override
        public String getFormat()
        {
            return null;
        }

        @Override
        public byte[] getEncoded()
        {
            return null;
        }
    }

    /**
     * The actual implementation of the Signature operation.
     */
    private static final class SignatureAdapter extends SignatureSpi
    {
        private final String _algorithm;
        private final ByteBuffer _buffer;

        private SignatureAdapter(String algorithm)
        {
            _algorithm = algorithm;
            _buffer = ByteBuffer.allocate(1024 * 4);
        }

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException
        {
            if (!(privateKey instanceof MarkerPrivateKey))
            {
                throw new InvalidKeyException();
            }
        }

        @Override
        protected void engineUpdate(byte b) throws SignatureException
        {
            _buffer.put(b);
        }

        @Override
        protected void engineUpdate(byte[] b, int off, int len) throws SignatureException
        {
            _buffer.put(b, off, len);
        }

        @Override
        protected byte[] engineSign() throws SignatureException
        {
            _buffer.flip(); // set buffer positions and limit for reading
            return ExternalSignatureSystem.sign(_buffer, _algorithm);
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException
        {
            throw new UnsupportedOperationException();
        }

        @Override
        protected boolean engineVerify(byte[] sigBytes) throws SignatureException
        {
            throw new UnsupportedOperationException();
        }

        @Override
        protected void engineSetParameter(String param, Object value) throws InvalidParameterException
        {
            throw new InvalidParameterException();
        }

        @Override
        protected Object engineGetParameter(String param) throws InvalidParameterException
        {
            throw new InvalidParameterException();
        }
    }
}
