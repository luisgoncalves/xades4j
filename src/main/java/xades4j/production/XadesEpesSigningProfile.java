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
import xades4j.providers.SignaturePolicyInfoProvider;

/**
 * A profile for producing XAdES-EPES signatures. A {@link KeyingDataProvider} and
 * a {@link SignaturePolicyInfoProvider} have to be supplied.
 * @see XadesSigningProfile
 * @author Luís
 */
public class XadesEpesSigningProfile extends XadesSigningProfile
{
    public XadesEpesSigningProfile(
            KeyingDataProvider keyingProvider,
            Class<? extends SignaturePolicyInfoProvider> policyInfoProviderClass)
    {
        super(keyingProvider);
        withBinding(SignaturePolicyInfoProvider.class, policyInfoProviderClass);
    }

    public XadesEpesSigningProfile(
            Class<? extends KeyingDataProvider> keyingProviderClass,
            Class<? extends SignaturePolicyInfoProvider> policyInfoProviderClass)
    {
        super(keyingProviderClass);
        withBinding(SignaturePolicyInfoProvider.class, policyInfoProviderClass);
    }

    public XadesEpesSigningProfile(
            KeyingDataProvider keyingProvider,
            SignaturePolicyInfoProvider policyInfoProvider)
    {
        super(keyingProvider);
        withBinding(SignaturePolicyInfoProvider.class, policyInfoProvider);
    }

    @Override
    protected Class<? extends XadesSigner> getSignerClass()
    {
        return SignerEPES.class;
    }
}
