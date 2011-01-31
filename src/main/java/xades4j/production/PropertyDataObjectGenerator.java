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

import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.PropertyDataObject;

/**
 * Interface for generators of property data objects. This is used during signature
 * generation to create the low-level data for a property. For each type of property
 * (Java class) there has to be a corresponding {@code PropertyDataObjectGenerator}.
 * <p>
 * This is one of the core items in signature generation since it may need to do
 * all the "heavy" work, such as calculating digests and obtaining time-stamp tokens.
 * <p>
 * Classes or instances of {@code PropertyDataObjectGenerator} for properties that
 * are not supported by the library have to be registered through the {@code withPropertyDataObjectGenerator}
 * method in a {@link XadesSigningProfile}. The library includes default implementations
 * for all the supported properties but these may be overriden.
 * <p>
 * The classes that implement this interface may have dependencies on other library
 * components (and also external components configured in the signing profile).
 * To that end, the constructors and/or setters should use the {@code Inject} annotation
 * from Guice.
 * @author Luís
 */
public interface PropertyDataObjectGenerator<TProp extends QualifyingProperty>
{
    PropertyDataObject generatePropertyData(
            TProp prop,
            PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException;
}
