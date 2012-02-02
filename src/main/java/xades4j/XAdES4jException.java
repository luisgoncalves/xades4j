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
package xades4j;

/**
 * Base class for all the library exceptions.
 * @author Luís
 */
public abstract class XAdES4jException extends Exception
{
    /**
     * Creates a new instance of <code>XAdES4jException</code> without detail message.
     */
    protected XAdES4jException()
    {
    }

    /**
     * Constructs an instance of <code>XAdES4jException</code> with the specified detail message.
     * @param msg the detail message.
     */
    protected XAdES4jException(String msg)
    {
        super(msg);
    }

    /**
     * Constructs an instance of <code>XAdES4jException</code> with the specified cause.
     * @param cause the cause.
     */
    protected XAdES4jException(Throwable cause)
    {
        super(cause);
    }

    /**
     * Constructs an instance of <code>XAdES4jException</code> with the specified
     * detail message and cause.
     * @param message the detail message
     * @param cause the cause
     */
    protected XAdES4jException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
