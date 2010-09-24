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
package xades4j;

/**
 * Thrown throughout the library when an algorithm (signature, digest, canonicalization)
 * is not supported by the library itself or by the underlying XML-DSIG implementation.
 * @author Luís
 */
public class UnsupportedAlgorithmException extends XAdES4jException
{
    private final String algorithm;

    public UnsupportedAlgorithmException(String algorithm)
    {
        this(null, algorithm);
    }

    public UnsupportedAlgorithmException(String msg, String algorithm)
    {
        super(msg);
        this.algorithm = algorithm;
    }

    public String getAlgorithm()
    {
        return algorithm;
    }
}
