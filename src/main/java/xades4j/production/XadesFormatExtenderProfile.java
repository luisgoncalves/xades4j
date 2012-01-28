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
import xades4j.utils.XadesProfileCore;
import xades4j.utils.XadesProfileResolutionException;
import xades4j.providers.AlgorithmsProvider;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.TimeStampTokenProvider;
import xades4j.utils.UtilsBindingsModule;
import xades4j.xml.marshalling.MarshallingBindingsModule;
import xades4j.xml.marshalling.UnsignedPropertiesMarshaller;
import xades4j.xml.marshalling.algorithms.AlgorithmParametersBindingsModule;

/**
 * A profile for signature format enrichment, after verification. A format extender
 * is used to add unsigned signature properties to an existing signature in order
 * augment its format. This can be done as part of the {@link xades4j.verification.XadesVerifier#verify(org.w3c.dom.Element, xades4j.verification.SignatureSpecificVerificationOptions, xades4j.production.XadesSignatureFormatExtender, xades4j.verification.XAdESForm) verification process}.
 * The {@code XadesSignatureFormatExtender} can also be used separately, but no
 * checks are made on the correctness of the signature.
 * <p>
 * This profile follows the same principles of {@link XadesSigningProfile}.
 * @author Luís
 */
public class XadesFormatExtenderProfile
{
    private final XadesProfileCore profileCore;

    public XadesFormatExtenderProfile()
    {
        this.profileCore = new XadesProfileCore();
    }

    public final <T> XadesFormatExtenderProfile withBinding(
            Class<T> from,
            Class<? extends T> to)
    {
        this.profileCore.addBinding(from, to);
        return this;
    }

    public final <T> XadesFormatExtenderProfile withBinding(
            Class<T> from,
            T to)
    {
        this.profileCore.addBinding(from, to);
        return this;
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

    public final XadesSignatureFormatExtender getFormatExtender() throws XadesProfileResolutionException
    {
        return this.profileCore.getInstance(getFormatExtenderClass(),overridableModules, sealedModules);
    }

    protected Class<? extends XadesSignatureFormatExtender> getFormatExtenderClass()
    {
        return XadesSignatureFormatExtenderImpl.class;
    }

    /**/
    /**
     * @deprecated This method is deprecated and might be removed on future versions
     * @see #withAlgorithmsProviderEx(xades4j.providers.AlgorithmsProviderEx)
     */
    public XadesFormatExtenderProfile withAlgorithmsProvider(
            AlgorithmsProvider algsProvider)
    {
        // Adapt AlgorithmsProviderEx to the AlgorithmsProvider being registered
        withBinding(AlgorithmsProviderEx.class, AlgorithmsProvider_DeprecatedToEx_Adapter.class);
        return withBinding(AlgorithmsProvider.class, algsProvider);
    }

    /**
     * @deprecated this method is deprecated and might be removed on future versions
     * @see #withAlgorithmsProviderEx(java.lang.Class)
     */
    public XadesFormatExtenderProfile withAlgorithmsProvider(
            Class<? extends AlgorithmsProvider> algsProviderClass)
    {
        // Adapt AlgorithmsProviderEx to the AlgorithmsProvider being registered
        withBinding(AlgorithmsProviderEx.class, AlgorithmsProvider_DeprecatedToEx_Adapter.class);
        return withBinding(AlgorithmsProvider.class, algsProviderClass);
    }

    public XadesFormatExtenderProfile withAlgorithmsProviderEx(
            AlgorithmsProviderEx algsProvider)
    {
        return withBinding(AlgorithmsProviderEx.class, algsProvider);
    }

    public XadesFormatExtenderProfile withAlgorithmsProviderEx(
            Class<? extends AlgorithmsProviderEx> algsProviderClass)
    {
        return withBinding(AlgorithmsProviderEx.class, algsProviderClass);
    }

    public XadesFormatExtenderProfile withDigestEngineProvider(
            MessageDigestEngineProvider digestProvider)
    {
        return withBinding(MessageDigestEngineProvider.class, digestProvider);
    }

    public XadesFormatExtenderProfile withDigestEngineProvider(
            Class<? extends MessageDigestEngineProvider> digestProviderClass)
    {
        return withBinding(MessageDigestEngineProvider.class, digestProviderClass);
    }

    public XadesFormatExtenderProfile withTimeStampTokenProvider(
            TimeStampTokenProvider tsTokenProvider)
    {
        return withBinding(TimeStampTokenProvider.class, tsTokenProvider);
    }

    public XadesFormatExtenderProfile withTimeStampTokenProvider(
            Class<? extends TimeStampTokenProvider> tsTokenProviderClass)
    {
        return withBinding(TimeStampTokenProvider.class, tsTokenProviderClass);
    }

    public XadesFormatExtenderProfile withUnsignedPropertiesMarshaller(
            UnsignedPropertiesMarshaller uPropsMarshaller)
    {
        return withBinding(UnsignedPropertiesMarshaller.class, uPropsMarshaller);
    }

    public XadesFormatExtenderProfile withUnsignedPropertiesMarshaller(
            Class<? extends UnsignedPropertiesMarshaller> uPropsMarshallerClass)
    {
        return withBinding(UnsignedPropertiesMarshaller.class, uPropsMarshallerClass);
    }

    /*******************************************/
    /****** Custom data object generation ******/
    /*******************************************/
    public <TProp extends QualifyingProperty> XadesFormatExtenderProfile withPropertyDataObjectGenerator(
            final Class<TProp> propClass,
            final PropertyDataObjectGenerator<TProp> propDataGen)
    {
        this.profileCore.addGenericBinding(PropertyDataObjectGenerator.class, propDataGen, propClass);
        return this;
    }

    public <TProp extends QualifyingProperty> XadesFormatExtenderProfile withPropertyDataObjectGenerator(
            final Class<TProp> propClass,
            final Class<? extends PropertyDataObjectGenerator<TProp>> propDataGenClass)
    {
        this.profileCore.addGenericBinding(PropertyDataObjectGenerator.class, propDataGenClass, propClass);
        return this;
    }
}
