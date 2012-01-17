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

import java.security.cert.X509Certificate;
import java.util.Collection;
import org.apache.xml.security.signature.XMLSignature;
import xades4j.properties.QualifyingProperties;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.SignedDataObjectProperty;
import xades4j.properties.SignedProperties;
import xades4j.properties.SignedSignatureProperty;
import xades4j.properties.UnsignedDataObjectProperty;
import xades4j.properties.UnsignedProperties;
import xades4j.properties.UnsignedSignatureProperty;
import xades4j.utils.DataGetter;
import xades4j.utils.DataGetterImpl;
import xades4j.providers.ValidationData;
import xades4j.utils.CollectionUtils;
import xades4j.utils.CollectionUtils.Projector;

/**
 * The result of signature verification. It includes the signature form, the qualifying
 * properties, the signed data objects and the validation data.
 * @author Luís
 */
public class XAdESVerificationResult
{
    private final XAdESForm signatureForm;
    private final XMLSignature xmlSignature;
    private final ValidationData validationData;
    private final Collection<PropertyInfo> properties;
    private final Collection<RawDataObjectDesc> signedDataObjects;
    /**/
    private final DataGetter<QualifyingProperty> propertiesGetter;
    private final QualifyingProperties qualifyingProperties;

    XAdESVerificationResult(
            XAdESForm signatureForm,
            XMLSignature xmlSignature,
            ValidationData validationData,
            Collection<PropertyInfo> properties,
            Collection<RawDataObjectDesc> signedDataObjects)
    {
        this.signatureForm = signatureForm;
        this.xmlSignature = xmlSignature;
        this.validationData = validationData;
        this.properties = properties;
        this.signedDataObjects = signedDataObjects;

        this.propertiesGetter = createPropsGetter(properties);
        this.qualifyingProperties = createQualifProps();
    }

    private DataGetter<QualifyingProperty> createPropsGetter(
            Collection<PropertyInfo> propsInfo)
    {
        Collection<QualifyingProperty> props = CollectionUtils.project(propsInfo, new Projector<PropertyInfo, QualifyingProperty>()
        {
            @Override
            public QualifyingProperty project(PropertyInfo e)
            {
                return e.getProperty();
            }
        });

        return new DataGetterImpl<QualifyingProperty>(props);
    }

    private QualifyingProperties createQualifProps()
    {
        Collection<QualifyingProperty> props = this.propertiesGetter.getAll();

        Collection<SignedSignatureProperty> ssp = CollectionUtils.filterByType(props, SignedSignatureProperty.class);
        Collection<SignedDataObjectProperty> sdop = CollectionUtils.filterByType(props, SignedDataObjectProperty.class);

        Collection<UnsignedSignatureProperty> usp = CollectionUtils.filterByType(props, UnsignedSignatureProperty.class);
        Collection<UnsignedDataObjectProperty> udop = CollectionUtils.filterByType(props, UnsignedDataObjectProperty.class);

        return new QualifyingProperties(
                new SignedProperties(ssp, sdop),
                new UnsignedProperties(usp, udop));
    }
    /**/
    /**/

    public XAdESForm getSignatureForm()
    {
        return signatureForm;
    }

    public XMLSignature getXmlSignature()
    {
        return xmlSignature;
    }

    public String getSignatureAlgorithmUri()
    {
        return xmlSignature.getSignedInfo().getSignatureMethodURI();
    }

    public String getCanonicalizationAlgorithmUri()
    {
        return xmlSignature.getSignedInfo().getCanonicalizationMethodURI();
    }

    /**
     * Gets the certificates and CRLs used to verify the signature.
     * @return the validation data
     */
    public ValidationData getValidationData()
    {
        return validationData;
    }

    /**
     * Gets the certificate that was used to verify the signature.
     * @return the certificate
     */
    public X509Certificate getValidationCertificate()
    {
        return validationData.getCerts().get(0);
    }

    /**
     * Gets a {@code DataGetter} that allows easy filtered access to the properties.
     * @return the filter
     */
    public DataGetter<QualifyingProperty> getPropertiesFilter()
    {
        return propertiesGetter;
    }

    /**
     * Gets pairs of properties and corresponding data objects if detailed information
     * is needed.
     * @return a collections of pairs of properties and data objects
     */
    public Collection<PropertyInfo> getPropertiesAndData()
    {
        return properties;
    }

    /**
     * Gets the whole set of qualifying properties in the signature, organized
     * by type.
     * @return the properties
     */
    public QualifyingProperties getQualifyingProperties()
    {
        return qualifyingProperties;
    }

    /**
     * Gets a representation of the signed data objects, which gives access to their
     * properties and {@code Reference}s.
     * @return the signed data objects
     */
    public Collection<RawDataObjectDesc> getSignedDataObjects()
    {
        return signedDataObjects;
    }
}
