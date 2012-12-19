/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Hubert Kario - QBS.
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
 * Container for validation data and verification result of a time stamp.
 * <p>
 * Contains both all certificate and CRLs used for verification of time stamp (in
 * {@code ValidationData} object), as well as the time inside the token.
 *
 * @author Hubert Kario
 *
 */
public class TimeStampVerificationData
{
    private final ValidationData validationData;
    private final Date timeStampDate;

    public TimeStampVerificationData(
            ValidationData validationData,
            Date timeFromTimeStampToken)
    {
        if (validationData == null || timeFromTimeStampToken == null)
            throw new NullPointerException("Neither ValidationData nor " +
                   "timeFromTimeStampToken parameters can be null");
        this.validationData = validationData;
        this.timeStampDate = timeFromTimeStampToken;
    }

    public ValidationData getValidationData()
    {
        return validationData;
    }

    public Date getTimeStampTokenTime()
    {
        return timeStampDate;
    }
}
