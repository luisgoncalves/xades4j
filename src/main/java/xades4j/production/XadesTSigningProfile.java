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
package xades4j.production;

import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SignaturePolicyInfoProvider;

/**
 * A profile for producing XAdES-T signatures. A {@link KeyingDataProvider} has
 * to be supplied. The library has a default {@link xades4j.providers.TimeStampTokenProvider}
 * that will be used to configure the {@code XadesSigner}. As all teh other components
 * it can be exchanged.
 * <p>
 * A {@link SignaturePolicyInfoProvider} should be added to produce a XAdES-T based
 * on XAdES-EPES.
 * @see XadesSigningProfile
 * @author Luís
 */
public class XadesTSigningProfile extends XadesSigningProfile
{
    public XadesTSigningProfile(
            Class<? extends KeyingDataProvider> keyingProviderClass)
    {
        super(keyingProviderClass);
    }

    public XadesTSigningProfile(KeyingDataProvider keyingProvider)
    {
        super(keyingProvider);
    }

    @Override
    protected Class<? extends XadesSigner> getSignerClass()
    {
        return SignerT.class;
    }

    public XadesTSigningProfile withPolicyProvider(
            SignaturePolicyInfoProvider policyInfoProvider)
    {
        withBinding(SignaturePolicyInfoProvider.class, policyInfoProvider);
        return this;
    }

    public XadesTSigningProfile withPolicyProvider(
            Class<? extends SignaturePolicyInfoProvider> policyInfoProviderClass)
    {
        withBinding(SignaturePolicyInfoProvider.class, policyInfoProviderClass);
        return this;
    }
}
