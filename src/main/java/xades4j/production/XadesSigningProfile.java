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

import com.google.inject.Module;
import xades4j.properties.QualifyingProperty;
import xades4j.providers.DataObjectPropertiesProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.SignaturePropertiesProvider;
import xades4j.providers.TimeStampTokenProvider;
import xades4j.providers.X500NameStyleProvider;
import xades4j.utils.UtilsBindingsModule;
import xades4j.utils.XadesProfileCore;
import xades4j.utils.XadesProfileResolutionException;
import xades4j.xml.marshalling.MarshallingBindingsModule;
import xades4j.xml.marshalling.SignedPropertiesMarshaller;
import xades4j.xml.marshalling.UnsignedPropertiesMarshaller;
import xades4j.xml.marshalling.algorithms.AlgorithmParametersBindingsModule;

/**
 * A profile for signature production. This class and its subclasses are the entry
 * point for producing signatures. A profile is a configuration for the signature
 * production process. This includes not only characteristics of the signer and the
 * signature, such as the signing key/certificate and signature properties, but also
 * components for the process itself, such as digest and time-stamp generation.
 * <p>
 * The purpose of this class is to configure a {@link XadesSigner} that will actually
 * produce signatures with those characteristics.
 * <p>
 * Only a {@link KeyingDataProvider} has to externally be supplied. All the other components
 * have default implementations that are used if no other actions are taken. However,
 * all of them can be replaced through the corresponding methods, either by an instance
 * or a class. When a class is used it may have dependencies on other components,
 * which will be handled in order to create the {@code XadesSigner}. The types may
 * also depend on external components, as long as that dependency is registered
 * with on of the {@code addBinding} methods. To that end, the constructors and/or
 * setters should use the {@code Inject} annotation from Guice.
 * <p>
 * Custom {@link PropertyDataObjectGenerator}s can also be configured. The principles
 * on their dependencies are the same.
 * <p>
 * The XAdES form is also part of the profile. Each form has additional requirements,
 * hence being defined by a specific subclass. There are profiles up to XAdES-C.
 * The extended formats are also supported (with a few limitations) but can only
 * be added after verfication ({@link xades4j.verification.XadesVerifier}).
 * <p>
 * Repeated dependency bindings will not cause an immediate error. An exception
 * will be thrown when an instance of {@code XadesSigner} is requested.
 *
 * @author Luís
 * @see XadesBesSigningProfile
 * @see XadesEpesSigningProfile
 * @see XadesTSigningProfile
 * @see XadesCSigningProfile
 * @see xades4j.utils.XadesProfileCore
 */
public abstract class XadesSigningProfile
{
    private final XadesProfileCore profileCore;

    protected XadesSigningProfile(KeyingDataProvider keyingProvider)
    {
        this.profileCore = new XadesProfileCore();
        withBinding(KeyingDataProvider.class, keyingProvider);
    }

    protected XadesSigningProfile(
            Class<? extends KeyingDataProvider> keyingProviderClass)
    {
        this.profileCore = new XadesProfileCore();
        withBinding(KeyingDataProvider.class, keyingProviderClass);
    }

    private static final Module[] overridableModules =
            {
                    new DefaultProductionBindingsModule(),
                    new MarshallingBindingsModule()
            };

    private static final Module[] sealedModules =
            {
                    new UtilsBindingsModule(),
                    new AlgorithmParametersBindingsModule()
            };

    /**
     * Creates a new {@code XadesSigner} based on the current state of the profile.
     * If any changes are made after this call, the previously returned signer will
     * not be affected. Other signers can be created, accumulating the profile changes.
     *
     * @return a {@code XadesSigner} accordingly to this profile
     * @throws XadesProfileResolutionException if the dependencies of the signer (direct and indirect) cannot be resolved
     */
    public final XadesSigner newSigner() throws XadesProfileResolutionException
    {
        return this.profileCore.getInstance(getSignerClass(), overridableModules, sealedModules);
    }

    protected abstract Class<? extends XadesSigner> getSignerClass();

    protected final <T> XadesSigningProfile withOptionalBinding(Class<T> clazz)
    {
        this.profileCore.addOptionalBinding(clazz);
        return this;
    }

    /**/

    /**
     * Adds a type dependency mapping to the profile. This is tipically done from an
     * interface to a type that implements that interface. When a dependency to
     * {@code from} is found, the {@code to} class is used. The {@code to} class
     * may in turn have its own dependencies.
     * <p>
     * The other {@code withNNNNNN} methods are convenient shortcuts for this one.
     *
     * @param from the dependency
     * @param to   the type that resolves the dependency
     * @return this profile
     */
    public final <T> XadesSigningProfile withBinding(
            Class<T> from,
            Class<? extends T> to)
    {
        this.profileCore.addBinding(from, to);
        return this;
    }

    /**
     * Adds a instance dependency mapping to the profile. When a dependency to
     * {@code from} is found, the {@code to} instance is used.
     * The other {@code withNNNNNN} methods are convenient shortcuts for this one.
     *
     * @param from the dependency
     * @param to   the instance that resolves the dependency
     * @return this profile
     */
    public final <T> XadesSigningProfile withBinding(
            Class<T> from,
            T to)
    {
        this.profileCore.addBinding(from, to);
        return this;
    }

    /**
     * Adds an instance dependency mapping to the profile, using the instance type as dependency.
     *
     * @param instance the instance that resolves the dependency
     * @return this profile
     */
    public final XadesSigningProfile with(Object instance)
    {
        this.profileCore.addBinding((Class<Object>) instance.getClass(), instance);
        return this;
    }

    /*
     **********************************************************************
     */

    public XadesSigningProfile withSignatureAlgorithms(SignatureAlgorithms algorithms)
    {
        return withBinding(SignatureAlgorithms.class, algorithms);
    }

    public XadesSigningProfile withDigestEngineProvider(
            MessageDigestEngineProvider digestProvider)
    {
        return withBinding(MessageDigestEngineProvider.class, digestProvider);
    }

    public XadesSigningProfile withDigestEngineProvider(
            Class<? extends MessageDigestEngineProvider> digestProviderClass)
    {
        return withBinding(MessageDigestEngineProvider.class, digestProviderClass);
    }

    /**
     * <b>Experimental API</b>. It may be changed or removed in future releases.
     */
    public XadesSigningProfile withX500NameStyleProvider(
            X500NameStyleProvider x500NameStyleProvider)
    {
        return withBinding(X500NameStyleProvider.class, x500NameStyleProvider);
    }

    /**
     * <b>Experimental API</b>. It may be changed or removed in future releases.
     */
    public XadesSigningProfile withX500NameStyleProvider(
            Class<? extends X500NameStyleProvider> x500NameStyleProviderClass)
    {
        return withBinding(X500NameStyleProvider.class, x500NameStyleProviderClass);
    }

    public XadesSigningProfile withBasicSignatureOptions(
            BasicSignatureOptions options)
    {
        return withBinding(BasicSignatureOptions.class, options);
    }

    public XadesSigningProfile withElementIdGenerator(ElementIdGeneratorFactory idGeneratorFactory)
    {
        return withBinding(ElementIdGeneratorFactory.class, idGeneratorFactory);
    }

    public XadesSigningProfile withElementIdGenerator(Class<? extends ElementIdGeneratorFactory> idGeneratorFactoryClass)
    {
        return withBinding(ElementIdGeneratorFactory.class, idGeneratorFactoryClass);
    }

    public XadesSigningProfile withSignaturePropertiesProvider(
            SignaturePropertiesProvider signaturePropsProv)
    {
        return withBinding(SignaturePropertiesProvider.class, signaturePropsProv);
    }

    public XadesSigningProfile withSignaturePropertiesProvider(
            Class<? extends SignaturePropertiesProvider> signaturePropsProvClass)
    {
        return withBinding(SignaturePropertiesProvider.class, signaturePropsProvClass);
    }

    public XadesSigningProfile withDataObjectPropertiesProvider(
            DataObjectPropertiesProvider dataObjPropsProvider)
    {
        return withBinding(DataObjectPropertiesProvider.class, dataObjPropsProvider);
    }

    public XadesSigningProfile withDataObjectPropertiesProvider(
            Class<? extends DataObjectPropertiesProvider> dataObjPropsProviderClass)
    {
        return withBinding(DataObjectPropertiesProvider.class, dataObjPropsProviderClass);
    }

    public XadesSigningProfile withTimeStampTokenProvider(
            TimeStampTokenProvider tsTokenProvider)
    {
        return withBinding(TimeStampTokenProvider.class, tsTokenProvider);
    }

    public XadesSigningProfile withTimeStampTokenProvider(
            Class<? extends TimeStampTokenProvider> tsTokenProviderClass)
    {
        return withBinding(TimeStampTokenProvider.class, tsTokenProviderClass);
    }

    public XadesSigningProfile withSignedPropertiesMarshaller(
            SignedPropertiesMarshaller sPropsMarshaller)
    {
        return withBinding(SignedPropertiesMarshaller.class, sPropsMarshaller);
    }

    public XadesSigningProfile withSignedPropertiesMarshaller(
            Class<? extends SignedPropertiesMarshaller> sPropsMarshallerClass)
    {
        return withBinding(SignedPropertiesMarshaller.class, sPropsMarshallerClass);
    }

    public XadesSigningProfile withUnsignedPropertiesMarshaller(
            UnsignedPropertiesMarshaller uPropsMarshaller)
    {
        return withBinding(UnsignedPropertiesMarshaller.class, uPropsMarshaller);
    }

    public XadesSigningProfile withUnsignedPropertiesMarshaller(
            Class<? extends UnsignedPropertiesMarshaller> uPropsMarshallerClass)
    {
        return withBinding(UnsignedPropertiesMarshaller.class, uPropsMarshallerClass);
    }

    /* ***************************************** */
    /* ***** Custom data object generation ***** */
    /* ***************************************** s*/
    public <TProp extends QualifyingProperty> XadesSigningProfile withPropertyDataObjectGenerator(
            final Class<TProp> propClass,
            final PropertyDataObjectGenerator<TProp> propDataGen)
    {
        this.profileCore.addGenericBinding(PropertyDataObjectGenerator.class, propDataGen, propClass);
        return this;
    }

    public <TProp extends QualifyingProperty> XadesSigningProfile withPropertyDataObjectGenerator(
            final Class<TProp> propClass,
            final Class<? extends PropertyDataObjectGenerator<TProp>> propDataGenClass)
    {
        this.profileCore.addGenericBinding(PropertyDataObjectGenerator.class, propDataGenClass, propClass);
        return this;
    }
}
