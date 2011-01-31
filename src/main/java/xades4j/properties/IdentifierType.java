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
 * The object {@code IdentifierType} as defined in XAdES.
 * 
 * &lt;xsd:complexType name=&quot;IdentifierType&quot;&gt;
 * 	&lt;xsd:simpleContent&gt;
 *		&lt;xsd:extension base=&quot;xsd:anyURI&quot;&gt;
 *			&lt;xsd:attribute name=&quot;Qualifier&quot; type=&quot;QualifierType&quot; use=&quot;optional&quot;/&gt;
 *		&lt;/xsd:extension&gt;
 *	&lt;/xsd:simpleContent&gt;
 * &lt;/xsd:complexType&gt;
 * &lt;xsd:simpleType name=&quot;QualifierType&quot;&gt;
 *	&lt;xsd:restriction base=&quot;xsd:string&quot;&gt;
 *		&lt;xsd:enumeration value=&quot;OIDAsURI&quot;/&gt;
 *		&lt;xsd:enumeration value=&quot;OIDAsURN&quot;/&gt;
 *	&lt;/xsd:restriction&gt;
 * &lt;/xsd:simpleType&gt
 * 
 * @author Luís
 */
public enum IdentifierType
{
    /**
     * The identifier is an URI.
     */
    URI,
    /**
     * The identifier is an Object IDentifier encoded as an URI
     */
    OIDAsURI,
    /**
     * The identifier is an Object IDentifier encoded as an URN
     */
    OIDAsURN
}
