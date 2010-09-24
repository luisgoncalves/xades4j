/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA
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
import xades4j.utils.CollectionUtils.Predicate;

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

        // Signed signature properties.
        Collection tmp = CollectionUtils.filter(props, new Predicate<QualifyingProperty>()
        {
            @Override
            public boolean verifiedBy(QualifyingProperty elem)
            {
                return elem instanceof SignedSignatureProperty;
            }
        });
        Collection<SignedSignatureProperty> ssp = (Collection<SignedSignatureProperty>)tmp;

        // Signed data object properties.
        tmp = CollectionUtils.filter(props, new Predicate<QualifyingProperty>()
        {
            @Override
            public boolean verifiedBy(QualifyingProperty elem)
            {
                return elem instanceof SignedDataObjectProperty;
            }
        });
        Collection<SignedDataObjectProperty> sdop = (Collection<SignedDataObjectProperty>)tmp;

        // Unsigned signature properties.
        tmp = CollectionUtils.filter(props, new Predicate<QualifyingProperty>()
        {
            @Override
            public boolean verifiedBy(QualifyingProperty elem)
            {
                return elem instanceof UnsignedSignatureProperty;
            }
        });
        Collection<UnsignedSignatureProperty> usp = (Collection<UnsignedSignatureProperty>)tmp;

        // Unsigned data object properties.
        tmp = CollectionUtils.filter(props, new Predicate<QualifyingProperty>()
        {
            @Override
            public boolean verifiedBy(QualifyingProperty elem)
            {
                return elem instanceof UnsignedDataObjectProperty;
            }
        });
        Collection<UnsignedDataObjectProperty> udop = (Collection<UnsignedDataObjectProperty>)tmp;

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
