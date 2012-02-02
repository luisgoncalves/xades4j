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
package xades4j.utils;

import xades4j.XAdES4jException;

/**
 * Thrown when an instance requested to a profile cannot be created. This is
 * probabily due to some missing dependencies or Guice annotations.
 * @author Luís
 */
public class XadesProfileResolutionException extends XAdES4jException
{
    public XadesProfileResolutionException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
