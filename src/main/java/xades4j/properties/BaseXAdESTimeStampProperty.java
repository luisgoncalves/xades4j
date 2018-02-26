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
package xades4j.properties;

import java.util.Date;

import xades4j.providers.ValidationData;

/**
 * Interface applicable to all TimeStampProperties used in XAdES signatures.
 * Provides the ability to query for time from time stamp token and validation data
 * used to verify the token.
 *
 * @author Hubert Kario
 *
 */
public interface BaseXAdESTimeStampProperty extends QualifyingProperty
{
    /**
     * Return the time at which the token claims to be generated.
     * <p>
     * Note: if there are multiple time stamp tokens in single property, only the time
     * from last one will be returned.
     * @return time from time stamp token in the property
     */
    public Date getTime();

    public void setTime(Date time);

    /**
     * Validation data (certificates and CRLs) used to check validity of the time stamp
     * token
     * <p>
     * Note: if there are multiple time stamp tokens in property, only validation data
     * for the last one will be returned.
     * @return validation data
     */
    public ValidationData getValidationData();

    public void setValidationData(ValidationData validationData);
}
