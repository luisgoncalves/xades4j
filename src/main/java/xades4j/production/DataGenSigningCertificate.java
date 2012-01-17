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

import com.google.inject.Inject;
import xades4j.properties.SigningCertificateProperty;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.SigningCertificateData;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.MessageDigestEngineProvider;

/**
 *
 * @author Luís
 */
class DataGenSigningCertificate
        extends DataGenBaseCertRefs
        implements PropertyDataObjectGenerator<SigningCertificateProperty>
{
    @Inject
    public DataGenSigningCertificate(
            AlgorithmsProviderEx algorithmsProvider,
            MessageDigestEngineProvider messageDigestProvider)
    {
        super(algorithmsProvider, messageDigestProvider);
    }

    @Override
    public PropertyDataObject generatePropertyData(
            SigningCertificateProperty prop,
            PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException
    {
        return super.generate(
                prop.getsigningCertificateChain(),
                new SigningCertificateData(),
                prop);
    }
}
