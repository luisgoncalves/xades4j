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

/**
 * A profile for producing XAdES-BES signatures. A {@link KeyingDataProvider} has
 * to be supplied.
 * @see XadesSigningProfile
 * @author Luís
 */
public final class XadesBesSigningProfile extends XadesSigningProfile
{
    public XadesBesSigningProfile(KeyingDataProvider keyingProvider)
    {
        super(keyingProvider);
    }

    public XadesBesSigningProfile(
            Class<? extends KeyingDataProvider> keyingProviderClass)
    {
        super(keyingProviderClass);
    }

    @Override
    protected Class<? extends XadesSigner> getSignerClass()
    {
        return SignerBES.class;
    }
}
