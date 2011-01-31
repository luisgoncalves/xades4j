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

import xades4j.properties.UnsignedProperties;
import xades4j.properties.SignedProperties;
import xades4j.properties.QualifyingProperties;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.UnsignedDataObjectProperty;
import xades4j.properties.UnsignedSignatureProperty;
import xades4j.properties.SignedSignatureProperty;
import xades4j.properties.SignedDataObjectProperty;
import xades4j.providers.DataObjectPropertiesProvider;
import xades4j.providers.SignaturePropertiesProvider;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Helper class that gathers the qualifying properties from the different providers
 * and data object desriptions.
 * @author Luís
 */
class QualifyingPropertiesProcessor
{
    private final SignaturePropertiesProvider sigPropsProvider;
    private final DataObjectPropertiesProvider dataObjPropsProvider;

    public QualifyingPropertiesProcessor(
            SignaturePropertiesProvider sigPropsProvider,
            DataObjectPropertiesProvider dataObjPropsProvider)
    {
        this.sigPropsProvider = sigPropsProvider;
        this.dataObjPropsProvider = dataObjPropsProvider;
    }

    QualifyingProperties getQualifyingProperties(
            SignedDataObjects dataObjs,
            Collection<SignedSignatureProperty> formatSpecificSignedSigProps,
            Collection<UnsignedSignatureProperty> formatSpecificUnsignedSigProps)
    {
        /* **** Signature properties **** */

        // Collect the signature properties from the provider.
        SignaturePropertiesCollectorImpl signaturePropsCollector = new SignaturePropertiesCollectorImpl();
        sigPropsProvider.provideProperties(signaturePropsCollector);

        Collection<SignedSignatureProperty> collectedSignedSigProps = signaturePropsCollector.getSignedSigProps();
        Collection<SignedSignatureProperty> signedSigProps = new ArrayList<SignedSignatureProperty>(
                collectedSignedSigProps.size() + formatSpecificSignedSigProps.size());
        signedSigProps.addAll(collectedSignedSigProps);
        signedSigProps.addAll(formatSpecificSignedSigProps);

        Collection<UnsignedSignatureProperty> collectedUnsignedSigProps = signaturePropsCollector.getUnsignedSigProps();
        Collection<UnsignedSignatureProperty> unsignedSigProps = new ArrayList<UnsignedSignatureProperty>(
                collectedUnsignedSigProps.size() + formatSpecificUnsignedSigProps.size());
        unsignedSigProps.addAll(collectedUnsignedSigProps);
        unsignedSigProps.addAll(formatSpecificUnsignedSigProps);

        /* **** Data objects properties **** */

        Collection<DataObjectDesc> dataObjsInfo = dataObjs.getDataObjectsDescs();

        // The containers for all the specified signed data object properties. Since
        // some properties can be applied to multiple data objects, we need to rule
        // out repeated references (a Set is used).
        Set<SignedDataObjectProperty> signedDataObjProps = new HashSet<SignedDataObjectProperty>(dataObjsInfo.size());
        Set<UnsignedDataObjectProperty> unsignedDataObjProps = new HashSet<UnsignedDataObjectProperty>(0);

        // Add the global data object properties.
        signedDataObjProps.addAll(dataObjs.getSignedDataObjsProperties());
        unsignedDataObjProps.addAll(dataObjs.getUnsignedDataObjsProperties());

        // Add the properties specified for each data object.
        for (DataObjectDesc dataObjInfo : dataObjsInfo)
        {
            // If no properties were specified allow the provider to add them.
            if (!dataObjInfo.hasProperties())
                this.dataObjPropsProvider.provideProperties(dataObjInfo);
            signedDataObjProps.addAll(dataObjInfo.getSignedDataObjProps());
            unsignedDataObjProps.addAll(dataObjInfo.getUnsignedDataObjProps());
        }

        /* **** */

        return new QualifyingProperties(
                new SignedProperties(signedSigProps, signedDataObjProps),
                new UnsignedProperties(unsignedSigProps, unsignedDataObjProps));
    }
}
