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
package xades4j.verification;

import xades4j.XAdES4jException;

/**
 * Throw during validation of the {@code CounterSignature} property if the XAdES
 * verification of the signature fails.
 * @author Luís
 */
public class CounterSignatureXadesVerificationException extends CounterSignatureVerificationException
{
    private final XAdES4jException cause;

    public CounterSignatureXadesVerificationException(XAdES4jException cause)
    {
        this.cause = cause;
    }

    @Override
    public XAdES4jException getCause()
    {
        return cause;
    }

    @Override
    protected String getVerificationMessage()
    {
        return cause.getMessage();
    }
}
