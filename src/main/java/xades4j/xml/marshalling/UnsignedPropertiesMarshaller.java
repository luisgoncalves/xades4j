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
package xades4j.xml.marshalling;

/**
 * Interface for unsigned properties data objects marshalling. Must support marshalling
 * into a DOM node that already contains properties, because it might be used to
 * extend an existing signature ({@link xades4j.production.XadesFormatExtenderProfile}).
 * In this case, the new property elements should added AFTER the existing ones.
 * @author Luís
 */
public interface UnsignedPropertiesMarshaller extends PropertiesMarshaller
{
}
