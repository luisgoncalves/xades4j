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

import com.google.inject.AbstractModule;
import com.google.inject.TypeLiteral;
import com.google.inject.multibindings.Multibinder;
import xades4j.properties.AllDataObjsCommitmentTypeProperty;
import xades4j.properties.AllDataObjsTimeStampProperty;
import xades4j.properties.ArchiveTimeStampProperty;
import xades4j.properties.CertificateValuesProperty;
import xades4j.properties.CommitmentTypeProperty;
import xades4j.properties.CompleteCertificateRefsProperty;
import xades4j.properties.CompleteRevocationRefsProperty;
import xades4j.properties.CounterSignatureProperty;
import xades4j.properties.DataObjectFormatProperty;
import xades4j.properties.IndividualDataObjsTimeStampProperty;
import xades4j.properties.RevocationValuesProperty;
import xades4j.properties.SigAndRefsTimeStampProperty;
import xades4j.properties.SignaturePolicyIdentifierProperty;
import xades4j.properties.SignaturePolicyImpliedProperty;
import xades4j.properties.SignatureProductionPlaceProperty;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.properties.SignerRoleProperty;
import xades4j.properties.SigningCertificateProperty;
import xades4j.properties.SigningTimeProperty;
import xades4j.properties.data.CustomPropertiesDataObjsStructureVerifier;
import xades4j.providers.DataObjectPropertiesProvider;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.SignaturePropertiesProvider;
import xades4j.providers.TimeStampTokenProvider;
import xades4j.providers.X500NameStyleProvider;
import xades4j.providers.impl.DefaultMessageDigestProvider;
import xades4j.providers.impl.DefaultSignaturePropertiesProvider;
import xades4j.providers.impl.DefaultX500NameStyleProvider;
import xades4j.providers.impl.HttpTimeStampTokenProvider;
import xades4j.providers.impl.HttpTsaConfiguration;

/**
 * Contains the Guice bindings for the default components and the bindings for the
 * needed internal components.
 *
 * @author Luís
 */
class DefaultProductionBindingsModule extends AbstractModule
{
    @Override
    protected void configure()
    {
        // Defaults for configurable components.
        bind(SignaturePropertiesProvider.class).to(DefaultSignaturePropertiesProvider.class);
        bind(DataObjectPropertiesProvider.class).toInstance(dataObj -> {
            // By default no properties are specified for a data object.
        });
        bind(SignatureAlgorithms.class).toInstance(new SignatureAlgorithms());
        bind(BasicSignatureOptions.class).toInstance(new BasicSignatureOptions());
        bind(MessageDigestEngineProvider.class).to(DefaultMessageDigestProvider.class);
        bind(X500NameStyleProvider.class).to(DefaultX500NameStyleProvider.class);
        bind(TimeStampTokenProvider.class).to(HttpTimeStampTokenProvider.class);
        bind(HttpTsaConfiguration.class).toProvider(() -> {
            throw new IllegalStateException("HttpTsaConfiguration must be configured in the profile in order to use an HTTP-based time-stamp token provider.");
        });
        bind(ElementIdGeneratorFactory.class).to(DefaultElementIdGeneratorFactory.class);

        // PropertiesDataObjectsGenerator is not configurable but the individual
        // generators may have dependencies.
        bind(PropertiesDataObjectsGenerator.class).to(PropertiesDataObjectsGeneratorImpl.class);
        bind(PropertyDataGeneratorsMapper.class).to(PropertyDataGeneratorsMapperImpl.class);
        // Ensure empty set when no bindings are defined
        Multibinder.newSetBinder(binder(), CustomPropertiesDataObjsStructureVerifier.class);

        // PropertyDataGeneratorsMapperImpl relies on the injector to get
        // the individual generators, so they need to be bound.
        // - SignedSignatureProperties
        bind(new TypeLiteral<PropertyDataObjectGenerator<SigningTimeProperty>>()
        {
        }).to(DataGenSigningTime.class);

        bind(new TypeLiteral<PropertyDataObjectGenerator<SignerRoleProperty>>()
        {
        }).to(DataGenSignerRole.class);

        bind(new TypeLiteral<PropertyDataObjectGenerator<SigningCertificateProperty>>()
        {
        }).to(DataGenSigningCertificate.class);

        bind(new TypeLiteral<PropertyDataObjectGenerator<SignatureProductionPlaceProperty>>()
        {
        }).to(DataGenSigProdPlace.class);

        bind(new TypeLiteral<PropertyDataObjectGenerator<SignaturePolicyIdentifierProperty>>()
        {
        }).to(DataGenSigPolicy.class);

        bind(new TypeLiteral<PropertyDataObjectGenerator<SignaturePolicyImpliedProperty>>()
        {
        }).to(DataGenSigPolicyImplied.class);

        // - SignedDataObjectProperties
        bind(new TypeLiteral<PropertyDataObjectGenerator<DataObjectFormatProperty>>()
        {
        }).to(DataGenDataObjFormat.class);

        bind(new TypeLiteral<PropertyDataObjectGenerator<CommitmentTypeProperty>>()
        {
        }).to(DataGenCommitmentType.class);

        bind(new TypeLiteral<PropertyDataObjectGenerator<AllDataObjsCommitmentTypeProperty>>()
        {
        }).to(DataGenCommitmentTypeAllDataObjs.class);

        bind(new TypeLiteral<PropertyDataObjectGenerator<IndividualDataObjsTimeStampProperty>>()
        {
        }).to(DataGenIndivDataObjsTimeStamp.class);

        bind(new TypeLiteral<PropertyDataObjectGenerator<AllDataObjsTimeStampProperty>>()
        {
        }).to(DataGenAllDataObjsTimeStamp.class);

        // - UnsignedSignatureProperties
        bind(new TypeLiteral<PropertyDataObjectGenerator<CounterSignatureProperty>>()
        {
        }).to(DataGenCounterSig.class);

        bind(new TypeLiteral<PropertyDataObjectGenerator<SignatureTimeStampProperty>>()
        {
        }).to(DataGenSigTimeStamp.class);

        bind(new TypeLiteral<PropertyDataObjectGenerator<CompleteCertificateRefsProperty>>()
        {
        }).to(DataGenCompleteCertRefs.class);

        bind(new TypeLiteral<PropertyDataObjectGenerator<CompleteRevocationRefsProperty>>()
        {
        }).to(DataGenCompleteRevocRefs.class);

        bind(new TypeLiteral<PropertyDataObjectGenerator<SigAndRefsTimeStampProperty>>()
        {
        }).to(DataGenSigAndRefsTimeStamp.class);

        bind(new TypeLiteral<PropertyDataObjectGenerator<CertificateValuesProperty>>()
        {
        }).to(DataGenCertificateValues.class);

        bind(new TypeLiteral<PropertyDataObjectGenerator<RevocationValuesProperty>>()
        {
        }).to(DataGenRevocationValues.class);

        bind(new TypeLiteral<PropertyDataObjectGenerator<ArchiveTimeStampProperty>>()
        {
        }).to(DataGenArchiveTimeStamp.class);
    }
}
