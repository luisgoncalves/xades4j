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
package xades4j.properties;

import java.util.Date;

import xades4j.providers.ValidationData;

/**
 * The {@code SignatureTimeStamp} property encapsulates the time-stamp over the
 * {@code ds:SignatureValue} element.
 * @author Luís
 */
public final class SignatureTimeStampProperty extends UnsignedSignatureProperty
    implements BaseXAdESTimeStampProperty
{
    public static final String PROP_NAME = "SignatureTimeStamp";
    private Date time;
    private ValidationData validationData;

    public SignatureTimeStampProperty()
    {
    }

    @Override
    public String getName()
    {
        return PROP_NAME;
    }

    @Override
    public Date getTime()
    {
        return time;
    }

    @Override
    public void setTime(Date time)
    {
        this.time = time;
    }

    @Override
    public ValidationData getValidationData()
    {
        return validationData;
    }

    @Override
    public void setValidationData(ValidationData validationData)
    {
        this.validationData = validationData;
    }
}
