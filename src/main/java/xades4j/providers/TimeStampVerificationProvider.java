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
package xades4j.providers;

import java.util.Date;

/**
 * Provides verification of time-stamp tokens. This is used whenever a time-stamp
 * property needs to be verified.
 * @author Luís
 */
public interface TimeStampVerificationProvider
{
    /**
     * Verifies a time-stamp token. This includes verifying the digest value and
     * the token signature, including the TSA certificate.
     * @param timeStampToken the encoded time-stamp token
     * @param tsDigestInput the input purportedly used in time-stamp creation, calculated from the current signature
     * @return the time-stamp
     * @throws TimeStampTokenVerificationException if the token cannot be validated (see subclasses of the exception)
     */
    public Date verifyToken(
            byte[] timeStampToken,
            byte[] tsDigestInput) throws TimeStampTokenVerificationException;
}
