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
 * Provider of time-stamp tokens. Used whenever a time-stamp token property is used.
 * The actual means of obtaining the token depend on the implementation.
 * <p>
 * A default implementation is provided.
 * @see xades4j.providers.impl.DefaultTimeStampTokenProvider
 * @author Luís
 */
public interface TimeStampTokenProvider
{
    public static class TimeStampTokenRes
    {
        public final byte[] encodedTimeStampToken;
        public final Date timeStampTime;

        public TimeStampTokenRes(byte[] encodedToken, Date timeStampTime)
        {
            this.encodedTimeStampToken = encodedToken;
            this.timeStampTime = timeStampTime;
        }
    }
    /**/

    /**
     * Gets a time-stamp token.
     * @param tsDigestInput the input for the digest to be sent to the TSA
     * @param digestAlgUri the digest algorithm that should be used to calculate the digest
     * @return the time-stamp token data
     * @throws TimeStampTokenGenerationException if there's an error getting the time-stamp
     */
    public TimeStampTokenRes getTimeStampToken(
            byte[] tsDigestInput,
            String digestAlgUri) throws TimeStampTokenGenerationException;
}
