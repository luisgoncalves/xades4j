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
import xades4j.XAdES4jException;

/**
 * Thrown when there is an error generating a property data object.
 * @author Luís
 */
public class PropertyDataGenerationException extends XAdES4jException
{
    private final QualifyingProperty sourceProperty;

    public PropertyDataGenerationException(QualifyingProperty sourceProperty, String message)
    {
        this(sourceProperty, message, null);
    }

    public PropertyDataGenerationException(QualifyingProperty sourceProperty, String message, Throwable cause)
    {
        super(message, cause);
        this.sourceProperty = sourceProperty;
    }

    /**
     * Gets the property instance that property that originated the exception.
     * @return the property
     */
    public QualifyingProperty getSourceProperty()
    {
        return sourceProperty;
    }

    @Override
    public String getMessage()
    {
        return String.format("Property data generation failed for %s: %s", sourceProperty.getName(), super.getMessage());
    }
}
