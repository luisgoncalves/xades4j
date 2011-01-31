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
