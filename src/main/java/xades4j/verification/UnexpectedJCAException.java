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

import xades4j.XAdES4jException;

/**
 * Thrown if there is an unexpected error when using the JCA. An example is the
 * absence of a provider for a service that should have default providers.
 * @author Luís
 */
public class UnexpectedJCAException extends XAdES4jException
{
    public UnexpectedJCAException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public UnexpectedJCAException(String msg)
    {
        super(msg);
    }
}
