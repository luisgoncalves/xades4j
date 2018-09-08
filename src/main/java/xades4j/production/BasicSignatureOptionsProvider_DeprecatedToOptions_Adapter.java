/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2018 Luis Goncalves.
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

import com.google.inject.Inject;
import com.google.inject.Provider;
import xades4j.providers.BasicSignatureOptionsProvider;

/**
 * Adapts the old {@link xades4j.providers.BasicSignatureOptionsProvider} to the
 * new {@link BasicSignatureOptions} class.
 * 
 * @author luis
 */
final class BasicSignatureOptionsProvider_DeprecatedToOptions_Adapter implements Provider<BasicSignatureOptions>
{
    private final BasicSignatureOptionsProvider provider;
    
    @Inject
    BasicSignatureOptionsProvider_DeprecatedToOptions_Adapter(BasicSignatureOptionsProvider provider)
    {
        this.provider = provider;
    }

    @Override
    public BasicSignatureOptions get()
    {
        return new BasicSignatureOptions()
                .includeSigningCertificate(this.provider.includeSigningCertificate())
                .includeSubjectName(this.provider.includeSigningCertificate())
                .includeIssuerSerial(this.provider.includeSigningCertificate())
                .includePublicKey(this.provider.includePublicKey())
                .signKeyInfo(this.provider.signSigningCertificate());
    }
}
