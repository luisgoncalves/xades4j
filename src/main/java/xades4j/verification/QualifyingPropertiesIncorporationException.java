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

/**
 * Thrown during signature verification if the signature doesn't fulfill the properties
 * incorporation rules. Note that the library doesn't support {@code QualifyingPropertiesReferece}s.
 * Examples of erros are: more that one {@code QualifyingProperties} element; invalid
 * {@code Target} attribute; the supposed {@code Reference} over {@code SignedProperties}
 * references another element (or not the one inside {@code QualifyingProperties}.
 * @author Luís
 */
public class QualifyingPropertiesIncorporationException extends InvalidSignatureException
{
    public QualifyingPropertiesIncorporationException(String msg)
    {
        super(msg);
    }

    public QualifyingPropertiesIncorporationException(String msg, Throwable cause)
    {
        super(msg, cause);
    }
}
