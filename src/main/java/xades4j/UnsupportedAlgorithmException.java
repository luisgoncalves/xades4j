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
 * Thrown throughout the library when an algorithm (signature, digest, canonicalization)
 * is not supported by the library itself or by the underlying XML-DSIG implementation.
 * @author Luís
 */
public class UnsupportedAlgorithmException extends XAdES4jException
{
    private final String algorithm;

    public UnsupportedAlgorithmException(String msg, String algorithm)
    {
        this(msg, algorithm, null);
    }

    public UnsupportedAlgorithmException(String msg, String algorithm, Throwable cause)
    {
        super(msg, cause);
        this.algorithm = algorithm;
    }

    @Override
    public String getMessage()
    {
        String msg = super.getMessage();
        if(null == msg)
            msg = "Unsupported algorithm";
        return String.format("%s (%s)", msg, this.getAlgorithm());
    }

    public String getAlgorithm()
    {
        return algorithm;
    }
}
