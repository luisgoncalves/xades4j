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
package xades4j.verification;

import com.google.inject.AbstractModule;
import com.google.inject.TypeLiteral;
import com.google.inject.multibindings.MapBinder;
import com.google.inject.multibindings.Multibinder;
import com.google.inject.util.Types;
import java.io.InputStream;
import java.lang.reflect.ParameterizedType;
import javax.xml.namespace.QName;
import xades4j.properties.CounterSignatureProperty;
import xades4j.properties.ObjectIdentifier;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.AllDataObjsTimeStampData;
import xades4j.properties.data.CommitmentTypeData;
import xades4j.properties.data.CompleteCertificateRefsData;
import xades4j.properties.data.CompleteRevocationRefsData;
import xades4j.properties.data.CustomPropertiesDataObjsStructureVerifier;
import xades4j.properties.data.DataObjectFormatData;
import xades4j.properties.data.GenericDOMData;
import xades4j.properties.data.IndividualDataObjsTimeStampData;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.SignaturePolicyData;
import xades4j.properties.data.SignatureProdPlaceData;
import xades4j.properties.data.SignatureTimeStampData;
import xades4j.properties.data.SignerRoleData;
import xades4j.properties.data.SigningCertificateData;
import xades4j.properties.data.SigningTimeData;
import xades4j.providers.impl.DefaultMessageDigestProvider;
import xades4j.providers.impl.DefaultTimeStampVerificationProvider;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.SignaturePolicyDocumentProvider;
import xades4j.providers.TimeStampVerificationProvider;
import xades4j.utils.BuiltIn;

/**
 * Contains the Guice bindings for the default components and the bindings for the
 * needed internal components.
 *
 * @author Luís
 */
class DefaultVerificationBindingsModule extends AbstractModule
{
    private <TData extends PropertyDataObject> void bindBuiltInVerifier(
            Class<TData> dataObjectClass,
            Class<? extends QualifyingPropertyVerifier<TData>> verifierClass)
    {
        ParameterizedType pt = Types.newParameterizedType(QualifyingPropertyVerifier.class, dataObjectClass);
        TypeLiteral<QualifyingPropertyVerifier<TData>> tl = (TypeLiteral<QualifyingPropertyVerifier<TData>>)TypeLiteral.get(pt);
        
        bind(tl).to(verifierClass);
        bind(tl).annotatedWith(BuiltIn.class).to(verifierClass);
    }

    @Override
    protected void configure()
    {
        bind(MessageDigestEngineProvider.class).to(DefaultMessageDigestProvider.class);
        bind(TimeStampVerificationProvider.class).to(DefaultTimeStampVerificationProvider.class);
        bind(SignaturePolicyDocumentProvider.class).toInstance(new SignaturePolicyDocumentProvider()
        {
            @Override
            public InputStream getSignaturePolicyDocumentStream(
                    ObjectIdentifier sigPolicyId)
            {
                return null;
            }
        });

        // QualifyingPropertiesVerifier is not configurable but the individual
        // verifiers may have dependencies.
        bind(QualifyingPropertiesVerifier.class).to(QualifyingPropertiesVerifierImpl.class);
        bind(QualifyingPropertyVerifiersMapper.class).to(QualifyingPropertyVerifiersMapperImpl.class);

//        customGlobalStructureVerifiers.add(new CustomPropertiesDataObjsStructureVerifier()
//        {
//            @Override
//            public void verifiy(DataGetter<PropertyDataObject> dataObjsGetter) throws PropertyDataStructureException
//            {
//                if (dataObjsGetter.getOfType(SigningCertificateData.class).isEmpty())
//                    throw new PropertyDataStructureException("property is required and isn't present", SigningCertificateProperty.PROP_NAME);
//            }
//        });

        // QualifyingPropertyVerifiersMapperImpl relies on the injector to get
        // the individual verifiers, so they need to be bound.
        // - SignedSignatureProperties
        bindBuiltInVerifier(SigningTimeData.class, SigningTimeVerifier.class);
        bindBuiltInVerifier(SignerRoleData.class, SignerRoleVerifier.class);
        bindBuiltInVerifier(SignatureProdPlaceData.class, SigProdPlaceVerifier.class);
        bindBuiltInVerifier(SigningCertificateData.class, SigningCertificateVerifier.class);
        bindBuiltInVerifier(SignaturePolicyData.class, SignaturePolicyVerifier.class);
        // - SignedDataObjectProperties
        bindBuiltInVerifier(CommitmentTypeData.class, CommitmentTypeVerifier.class);
        bindBuiltInVerifier(DataObjectFormatData.class, DataObjFormatVerifier.class);
        bindBuiltInVerifier(AllDataObjsTimeStampData.class, AllDataObjsTimeStampVerifier.class);
        bindBuiltInVerifier(IndividualDataObjsTimeStampData.class, IndivDataObjsTimeStampVerifier.class);
        // - UnsignedSignatureProperties
        bindBuiltInVerifier(SignatureTimeStampData.class, SignatureTimeStampVerifier.class);
        bindBuiltInVerifier(CompleteCertificateRefsData.class, CompleteCertRefsVerifier.class);
        bindBuiltInVerifier(CompleteRevocationRefsData.class, CompleteRevocRefsVerifier.class);
        
        MapBinder<QName, QualifyingPropertyVerifier> unkownElemsBinder = MapBinder.newMapBinder(binder(), QName.class, QualifyingPropertyVerifier.class);
        unkownElemsBinder
                .addBinding(new QName(QualifyingProperty.XADES_XMLNS, CounterSignatureProperty.PROP_NAME))
                .to(CounterSignatureVerifier.class);

        // Verification based on XML elements names.
        bind(new TypeLiteral<QualifyingPropertyVerifier<GenericDOMData>>()
        {
        }).to(GenericDOMDataVerifier.class);

        // Ensure empty sets when no bindings are defined
        Multibinder.newSetBinder(binder(), RawSignatureVerifier.class);
        Multibinder.newSetBinder(binder(), CustomSignatureVerifier.class);
        Multibinder.newSetBinder(binder(), CustomPropertiesDataObjsStructureVerifier.class);
    }
}
