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
package xades4j.properties;

/**
 * Base interface for all the qualifying properties.
 * @author Luís
 */
public interface QualifyingProperty
{
    /**
     * The XAdES v1.3.2 namespace URI.
     */
    public static final String XADES_XMLNS = "http://uri.etsi.org/01903/v1.3.2#";
    /**
     * The XAdES v1.4.1 namespaceURI.
     */
    public static final String XADESV141_XMLNS = "http://uri.etsi.org/01903/v1.4.1#";
    /**
     * The name of the {@code QualifyingProperties} element.
     */
    public static final String QUALIFYING_PROPS_TAG = "QualifyingProperties";
        /**
     * The name of the {@code Target} attribute.
     */
    public static final String TARGET_ATTR = "Target";
    /**
     * The name of the {@code QualifyingPropertiesReference} element.
     */
    public static final String QUALIFYING_PROPS_REF_TAG = "QualifyingPropertiesReference";
    /**
     * The URI of the signed properties reference type. To be used in {@code ds:Reference}.
     */
    public static final String SIGNED_PROPS_TYPE_URI = "http://uri.etsi.org/01903#SignedProperties";
        /**
     * The name of the {@code SignedProperties} element.
     */
    public static final String SIGNED_PROPS_TAG = "SignedProperties";
            /**
     * The name of the {@code SignedSignatureProperties} element.
     */
    public static final String SIGNED_SIGNATURE_PROPS_TAG = "SignedSignatureProperties";
                /**
     * The name of the {@code SignedDataObjectProperties} element.
     */
    public static final String SIGNED_DATAOBJ_PROPS_TAG = "SignedDataObjectProperties";
        /**
     * The name of the {@code UnsignedProperties} element.
     */
    public static final String UNSIGNED_PROPS_TAG = "UnsignedProperties";
            /**
     * The name of the {@code UnsignedSignatureProperties} element.
     */
    public static final String UNSIGNED_SIGNATURE_PROPS_TAG = "UnsignedSignatureProperties";
                /**
     * The name of the {@code UnsignedDataObjectProperties} element.
     */
    public static final String UNSIGNED_DATAOBJ_PROPS_TAG = "UnsignedDataObjectProperties";
    /**/
    /**
     * Indicates wether the property is a signed property.
     * @return {@code true} if this is a signed property
     */
    public boolean isSigned();

    /**
     * Indicates wether the property is a signature property.
     * @return {@code true} if this is a signature property
     */
    public boolean isSignature();

    /**
     * Gets the name of the property, as specified in XAdES (the element name).
     * @return the name
     */
    public String getName();
}
