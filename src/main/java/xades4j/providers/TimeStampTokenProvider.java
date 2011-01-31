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
