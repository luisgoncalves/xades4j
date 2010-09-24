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

import java.util.Date;
import java.util.List;
import xades4j.utils.TimeStampDigestInput;
import xades4j.properties.data.BaseXAdESTimeStampData;
import xades4j.providers.TimeStampTokenDigestException;
import xades4j.providers.TimeStampTokenSignatureException;
import xades4j.providers.TimeStampTokenStructureException;
import xades4j.providers.TimeStampTokenVerificationException;
import xades4j.providers.TimeStampVerificationProvider;

/**
 *
 * @author Luís
 */
class TimeStampUtils
{
    static TimeStampVerificationException getEx(
            final TimeStampTokenVerificationException ex,
            String propName)
    {
        if (ex instanceof TimeStampTokenDigestException)
            return new TimeStampDigestMismatchException(propName);

        if (ex instanceof TimeStampTokenSignatureException)
            return new TimeStampInvalidSignatureException(propName, ex.getMessage());

        if (ex instanceof TimeStampTokenStructureException)
            return new TimeStampInvalidTokenException(propName, ex.getMessage());

        return new TimeStampVerificationException(propName)
        {
            @Override
            protected String getVerificationMessage()
            {
                return ex.getMessage();
            }
        };
    }

    /**
     * Verifies the time-stamp tokne on a time-stamp property data object. Only
     * the FIRST token is verified.
     * @param tsData the time-stamp property data object
     * @param digestInput the calculated input for the digest that will be matched with the one in the time-stamp
     * @param verifier the time-stamp verifier
     * @param propName the name of the property being verified (for exceptions)
     * @return the time-stamp time of the first token
     */
    static Date verifyTokens(
            BaseXAdESTimeStampData tsData,
            TimeStampDigestInput digestInput,
            TimeStampVerificationProvider verifier,
            String propName) throws TimeStampVerificationException
    {
        try
        {
            byte[] data = digestInput.getBytes();
            List<byte[]> tokens = tsData.getTimeStampTokens();
            if (tokens.size() > 1)
                throw new TimeStampVerificationException(propName)
                {
                    @Override
                    protected String getVerificationMessage()
                    {
                        return "multiple timestamp tokens are not supported";
                    }
                };
            return verifier.verifyToken(tokens.get(0), data);
        } catch (TimeStampTokenVerificationException ex)
        {
            throw TimeStampUtils.getEx(ex, propName);
        }
    }
}
