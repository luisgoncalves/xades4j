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
package xades4j.production;

import xades4j.providers.KeyingDataProvider;
import xades4j.providers.ValidationDataProvider;

/**
 * A profile for producing XAdES-C signatures. A {@link KeyingDataProvider} and
 * a {@link ValidationDataProvider} have to be supplied.
 * <p>
 * A {@link xades4j.providers.SignaturePolicyInfoProvider} should be added to produce
 * a XAdES-C based on XAdES-EPES.
 * <p>
 * The {@code AttributeCertificateRefs} and {@code AttributeRevocationRefs} properties
 * are not supported.
 * @author Luís
 */
public class XadesCSigningProfile extends XadesTSigningProfile
{
    public XadesCSigningProfile(
            KeyingDataProvider keyingProvider,
            ValidationDataProvider validationDataProv)
    {
        super(keyingProvider);
        withBinding(ValidationDataProvider.class, validationDataProv);
    }

    public XadesCSigningProfile(
            KeyingDataProvider keyingProvider,
            Class<? extends ValidationDataProvider> validationDataProvClass)
    {
        super(keyingProvider);
        withBinding(ValidationDataProvider.class, validationDataProvClass);
    }

    public XadesCSigningProfile(
            Class<? extends KeyingDataProvider> keyingProviderClass,
            ValidationDataProvider validationDataProv)
    {
        super(keyingProviderClass);
        withBinding(ValidationDataProvider.class, validationDataProv);
    }

    public XadesCSigningProfile(
            Class<? extends KeyingDataProvider> keyingProviderClass,
            Class<? extends ValidationDataProvider> validationDataProvClass)
    {
        super(keyingProviderClass);
        withBinding(ValidationDataProvider.class, validationDataProvClass);
    }

    @Override
    protected Class<? extends XadesSigner> getSignerClass()
    {
        return SignerC.class;
    }
}
