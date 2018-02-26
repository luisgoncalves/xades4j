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

import com.google.inject.Module;
import javax.xml.namespace.QName;
import xades4j.utils.XadesProfileCore;
import xades4j.utils.XadesProfileResolutionException;
import xades4j.properties.data.CustomPropertiesDataObjsStructureVerifier;
import xades4j.properties.data.PropertyDataObject;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.SignaturePolicyDocumentProvider;
import xades4j.providers.TSACertificateValidationProvider;
import xades4j.providers.TimeStampVerificationProvider;
import xades4j.utils.UtilsBindingsModule;
import xades4j.xml.marshalling.algorithms.AlgorithmParametersBindingsModule;
import xades4j.xml.unmarshalling.QualifyingPropertiesUnmarshaller;
import xades4j.xml.unmarshalling.UnmarshallingBindingsModule;

/**
 * A profile for signature verification. This class is the entry point for verifying
 * a signature. A profile is a configuration for the signature verification process.
 * <p>
 * The purpose of this class is to create a {@link XadesVerifier} that will actually
 * verify signatures using the configured components.
 * <p>
 * The minimum configuration is a {@link xades4j.providers.CertificateValidationProvider}
 * because the validation data (trust-anchors, CRLs, etc) has to be properly selected.
 * All the other components
 * have default implementations that are used if no other actions are taken. However,
 * all of them can be replaced through the corresponding methods, either by an instance
 * or a class. When a class is used it may have dependencies on other components,
 * which will be handled in order to create the {@code XadesVerifier}. The types may
 * also depend on external components, as long as that dependency is registered
 * with on of the {@code addBinding} methods. To that end, the constructors and/or
 * setters should use the {@code Inject} annotation from Guice.
 * <p>
 * Custom {@link QualifyingPropertyVerifier}s can also be configured. The principles
 * on their dependencies are the same. In addition, custom verifiers that apply 
 * over the whole on different stages of validation can be configured. Finally,
 * verifiers for specific XML elements may be added. This can be useful if one
 * wants to handle an unsigned property that is not known by the library, as the
 * default unmarshaller will create {@code GenericDOMData} instances for those
 * properties if {@code acceptUnknownProperties} is set.
 * <p>
 * Repeated dependency bindings will not cause an immediate error. An exception
 * will be thrown when an instance of {@code XadesVerifier} is requested.
 * @author Luís
 */
public final class XadesVerificationProfile
{
    private final XadesProfileCore profileCore;
    /**/
    private boolean acceptUnknownProperties;
    private boolean secureValidation;

    private XadesVerificationProfile()
    {
        this.profileCore = new XadesProfileCore();
        this.acceptUnknownProperties = false;
        this.secureValidation = false;
        withBinding(XadesVerifier.class, XadesHybridVerifierImpl.class);
    }

    /**
     * Certificate validation profile to be used only with signatures lacking time stamps
     *
     * @param certificateValidationProvider
     */
    public XadesVerificationProfile(
            CertificateValidationProvider certificateValidationProvider)
    {
        this();
        withBinding(CertificateValidationProvider.class, certificateValidationProvider);
    }

    /**
     * Certificate validation profile that can be used to validate both signature and
     * time stamps in XML Advanced Electronic Signatures.
     *
     * @param certificateValidationProvider validation data and provider to be used for
     * validation Signature only
     * @param tsaCertificateValidationProvider validation data and provider to be used for
     * validation of time stamps in signature
     */
    public XadesVerificationProfile(
            CertificateValidationProvider certificateValidationProvider,
            TSACertificateValidationProvider tsaCertificateValidationProvider)
    {
        this();
        withBinding(CertificateValidationProvider.class, certificateValidationProvider);
        withBinding(TSACertificateValidationProvider.class, tsaCertificateValidationProvider);
    }

    public XadesVerificationProfile(
            Class<? extends CertificateValidationProvider> certificateValidationProviderClass)
    {
        this();
        withBinding(CertificateValidationProvider.class, certificateValidationProviderClass);
    }

    public XadesVerificationProfile(
            Class<? extends CertificateValidationProvider> certificateValidationProviderClass,
            Class<? extends TSACertificateValidationProvider> tsaCertificateValProvClass)
    {
        this();
        withBinding(CertificateValidationProvider.class, certificateValidationProviderClass);
        withBinding(TSACertificateValidationProvider.class, tsaCertificateValProvClass);
    }

    /**
     * Adds a type dependency mapping to the profile. This is typically done from an
     * interface to a type that implements that interface. When a dependency to
     * {@code from} is found, the {@code to} class is used. The {@code to} class
     * may in turn have its own dependencies.
     * <p>
     * The other {@code withNNNNNN} methods are convenient shortcuts for this one.
     * @param from the dependency
     * @param to the type that resolves the dependency
     * @return this profile
     */
    public <T> XadesVerificationProfile withBinding(
            Class<T> from,
            Class<? extends T> to)
    {
        profileCore.addBinding(from, to);
        return this;
    }

    /**
     * Adds a instance dependency mapping to the profile. When a dependency to
     * {@code from} is found, the {@code to} instance is used.
     * The other {@code withNNNNNN} methods are convenient shortcuts for this one.
     * @param from the dependency
     * @param to the instance that resolves the dependency
     * @return this profile
     */
    public <T> XadesVerificationProfile withBinding(
            Class<T> from,
            T to)
    {
        profileCore.addBinding(from, to);
        return this;
    }

    private static final Module[] overridableModules =
    {
        new DefaultVerificationBindingsModule(),
        new UnmarshallingBindingsModule()
    };

    private static final Module[] sealedModules =
    {
        new UtilsBindingsModule(),
        new AlgorithmParametersBindingsModule()
    };

    /**
     * Creates a new {@code XadesVerifier} based on the current state of the profile.
     * If any changes are made after this call, the previously returned verifier will
     * not be affected. Other verifiers can be created, accumulating the profile changes.
     * @return a {@code XadesVerifier} accordingly to this profile.
     * @throws XadesProfileResolutionException if the dependencies of the signer (direct and indirect) cannot be resolved
     * @see XadesVerifier
     */
    public final XadesVerifier newVerifier() throws XadesProfileResolutionException
    {
        XadesHybridVerifierImpl v = profileCore.getInstance(XadesHybridVerifierImpl.class, overridableModules, sealedModules);
        v.setAcceptUnknownProperties(acceptUnknownProperties);
        v.setSecureValidation(secureValidation);
        return v;
    }

    /****/
    public XadesVerificationProfile withDigestEngineProvider(
            MessageDigestEngineProvider digestProvider)
    {
        return withBinding(MessageDigestEngineProvider.class, digestProvider);
    }

    public XadesVerificationProfile withDigestEngineProvider(
            Class<? extends MessageDigestEngineProvider> digestProviderClass)
    {
        return withBinding(MessageDigestEngineProvider.class, digestProviderClass);
    }

    /**
     * By default no policies are supported.
     */
    public XadesVerificationProfile withPolicyDocumentProvider(
            SignaturePolicyDocumentProvider policyDocProvider)
    {
        return withBinding(SignaturePolicyDocumentProvider.class, policyDocProvider);
    }

    /**
     * By default no policies are supported.
     */
    public XadesVerificationProfile withPolicyDocumentProvider(
            Class<? extends SignaturePolicyDocumentProvider> policyDocProviderClass)
    {
        return withBinding(SignaturePolicyDocumentProvider.class, policyDocProviderClass);
    }

    public XadesVerificationProfile withTimeStampTokenVerifier(
            TimeStampVerificationProvider tsTokenVerifProv)
    {
        return withBinding(TimeStampVerificationProvider.class, tsTokenVerifProv);
    }

    public XadesVerificationProfile withTimeStampTokenVerifier(
            Class<? extends TimeStampVerificationProvider> tsTokenVerifProvClass)
    {
        return withBinding(TimeStampVerificationProvider.class, tsTokenVerifProvClass);
    }

    public XadesVerificationProfile withPropertiesUnmarshaller(
            QualifyingPropertiesUnmarshaller propsUnmarshaller)
    {
        return withBinding(QualifyingPropertiesUnmarshaller.class, propsUnmarshaller);
    }

    public XadesVerificationProfile withPropertiesUnmarshaller(
            Class<? extends QualifyingPropertiesUnmarshaller> propsUnmarshallerClass)
    {
        return withBinding(QualifyingPropertiesUnmarshaller.class, propsUnmarshallerClass);
    }

    /**
     * Indicates whether the resulting verifiers should accept unknown properties.
     * Actually, this is a property of the underlying {@code QualifyingPropertiesUnmarshaller}
     * which controls if a {@code GenericDOMData} should be used when an unknown
     * property is found.
     * <p>
     * The schema for signed signature and data object properties is closed; as
     * such, this only affects the unsigned properties.
     * <p>
     * Note that it is also possible to implement a custom {@code QualifyingPropertiesUnmarshaller}s.
     * <p>
     * The {@link XadesVerificationProfile#withElementVerifier withElementVerifier}
     * method can be used to register verifiers for unknown properties.
     * @see xades4j.xml.unmarshalling.QualifyingPropertiesUnmarshaller
     */
    public XadesVerificationProfile acceptUnknownProperties(boolean accept)
    {
        this.acceptUnknownProperties = accept;
        return this;
    }

    /**
     * If true, it will perform the digital enforcing the following restrictions:
     *      1. Forbids use of the XSLT Transform
     *      2. Restricts the number of SignedInfo or Manifest References to 30 or less
     *      3. Restricts the number of Reference Transforms to 5 or less
     *      4. Forbids the use of MD5 related signature or mac algorithms
     *      5. Ensures that Reference Ids are unique to help prevent signature wrapping attacks
     *      6. Forbids Reference URIs of type http or file
     *      7. Does not allow a RetrievalMethod to reference another RetrievalMethod
     */
    public XadesVerificationProfile withSecureValidation(boolean secureValidation)
    {
        this.secureValidation = secureValidation;
        return this;
    }

    /**********************************************/
    /************ Custom verification *************/
    /**********************************************/
    public XadesVerificationProfile withGlobalDataObjsStructureVerifier(
            CustomPropertiesDataObjsStructureVerifier v)
    {
        if (null == v)
            throw new NullPointerException();

        this.profileCore.addMultibinding(CustomPropertiesDataObjsStructureVerifier.class, v);
        return this;
    }

    public XadesVerificationProfile withGlobalDataObjsStructureVerifier(
            Class<? extends CustomPropertiesDataObjsStructureVerifier> customVerifierClass)
    {
        if (null == customVerifierClass)
            throw new NullPointerException();

        this.profileCore.addMultibinding(CustomPropertiesDataObjsStructureVerifier.class, customVerifierClass);
        return this;
    }

    public XadesVerificationProfile withRawSignatureVerifier(
            RawSignatureVerifier v)
    {
        if (null == v)
            throw new NullPointerException();

        this.profileCore.addMultibinding(RawSignatureVerifier.class, v);
        return this;
    }

    public XadesVerificationProfile withRawSignatureVerifier(
            Class<? extends RawSignatureVerifier> rawVerifierClass)
    {
        if (null == rawVerifierClass)
            throw new NullPointerException();

        this.profileCore.addMultibinding(RawSignatureVerifier.class, rawVerifierClass);
        return this;
    }

    public XadesVerificationProfile withCustomSignatureVerifier(
            CustomSignatureVerifier v)
    {
        if (null == v)
            throw new NullPointerException();

        this.profileCore.addMultibinding(CustomSignatureVerifier.class, v);
        return this;
    }

    public XadesVerificationProfile withCustomSignatureVerifier(
            Class<? extends CustomSignatureVerifier> customVerifierClass)
    {
        if (null == customVerifierClass)
            throw new NullPointerException();

        this.profileCore.addMultibinding(CustomSignatureVerifier.class, customVerifierClass);
        return this;
    }

    public XadesVerificationProfile withElementVerifier(
            QName elemName, Class<? extends QualifyingPropertyVerifier<?>> vClass)
    {
        if (null == elemName || null == vClass)
            throw new NullPointerException();

        this.profileCore.addMapBinding(QualifyingPropertyVerifier.class, elemName, vClass);
        return this;
    }

    public <TData extends PropertyDataObject> XadesVerificationProfile withQualifyingPropertyVerifier(
            Class<TData> propDataClass,
            Class<? extends QualifyingPropertyVerifier<TData>> verifierClass)
    {
        this.profileCore.addGenericBinding(QualifyingPropertyVerifier.class, verifierClass, propDataClass);
        return this;
    }

    public <TData extends PropertyDataObject> XadesVerificationProfile withQualifyingPropertyVerifier(
            Class<TData> propDataClass,
            QualifyingPropertyVerifier<TData> verifier)
    {
        this.profileCore.addGenericBinding(QualifyingPropertyVerifier.class, verifier, propDataClass);
        return this;
    }
}
