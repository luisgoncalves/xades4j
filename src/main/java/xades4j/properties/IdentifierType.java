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
