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

import javax.inject.Inject;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import com.google.common.base.Optional;
import xades4j.properties.SignedSignatureProperty;
import xades4j.properties.UnsignedSignatureProperty;
import xades4j.XAdES4jException;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.DataObjectPropertiesProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SignaturePolicyInfoProvider;
import xades4j.providers.SignaturePropertiesProvider;
import xades4j.providers.X500NameStyleProvider;
import xades4j.utils.PropertiesUtils;
import xades4j.xml.marshalling.SignedPropertiesMarshaller;
import xades4j.xml.marshalling.UnsignedPropertiesMarshaller;
import xades4j.xml.marshalling.algorithms.AlgorithmsParametersMarshallingProvider;

/**
 * Produces XAdES-T signatures. Doesn't extend SignerEPES because XAdES-T may be
 * based on XAdES-BES. If T+EPES is needed, a {@code SignaturePolicyInfoProvider}
 * will be injected after construction via {@code setPolicyProvider}.
 * @author Luís
 */
class SignerT extends SignerBES
{
    private Optional<SignaturePolicyInfoProvider> policyInfoProvider;

    @Inject
    protected SignerT(
            KeyingDataProvider keyingProvider,
            AlgorithmsProviderEx algorithmsProvider,
            BasicSignatureOptions basicSignatureOptions,
            SignedDataObjectsProcessor dataObjectDescsProcessor,
            SignaturePropertiesProvider signaturePropsProvider,
            DataObjectPropertiesProvider dataObjPropsProvider,
            PropertiesDataObjectsGenerator propsDataObjectsGenerator,
            SignedPropertiesMarshaller signedPropsMarshaller,
            UnsignedPropertiesMarshaller unsignedPropsMarshaller,
            AlgorithmsParametersMarshallingProvider algorithmsParametersMarshaller,
            X500NameStyleProvider x500NameStyleProvider,
            Optional<SignaturePolicyInfoProvider> policyInfoProvider)
    {
        super(keyingProvider, algorithmsProvider, basicSignatureOptions, dataObjectDescsProcessor, signaturePropsProvider, dataObjPropsProvider, propsDataObjectsGenerator, signedPropsMarshaller, unsignedPropsMarshaller, algorithmsParametersMarshaller, x500NameStyleProvider);
        this.policyInfoProvider = policyInfoProvider;
    }

    @Override
    protected void getFormatSpecificSignatureProperties(
            Collection<SignedSignatureProperty> formatSpecificSignedSigProps,
            Collection<UnsignedSignatureProperty> formatSpecificUnsignedSigProps,
            List<X509Certificate> signingCertificateChain) throws XAdES4jException
    {
        super.getFormatSpecificSignatureProperties(
                formatSpecificSignedSigProps, formatSpecificUnsignedSigProps, signingCertificateChain);

        // Check if this is based on XAdES-EPES.
        if (this.policyInfoProvider.isPresent())
        {
            PropertiesUtils.addXadesEpesProperties(formatSpecificSignedSigProps, this.policyInfoProvider.get());
        }
        // Add XAdES-T.
        PropertiesUtils.addXadesTProperties(formatSpecificUnsignedSigProps);
    }
}
