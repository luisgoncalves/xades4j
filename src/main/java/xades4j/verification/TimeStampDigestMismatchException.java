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

/**
 * Thrown during verification of time-stamp properties if the actual digest of the
 * data covered by the time-stamp is different from the digest within the time-stamp.
 * @author Luís
 */
public class TimeStampDigestMismatchException extends TimeStampVerificationException
{
    public TimeStampDigestMismatchException(String propName)
    {
        super(propName);
    }

    @Override
    protected String getVerificationMessage()
    {
        return "input digest and token message imprint mismatch";
    }

}
