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
