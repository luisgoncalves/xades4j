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

import java.text.DateFormat;
import java.util.Date;
import xades4j.properties.SigningTimeProperty;

/**
 * Thrown during verification of the {@code SigningTime} property if the time contained
 * in the property is not before the verification time.
 * @author Luís
 */
public class SigningTimeVerificationException extends InvalidPropertyException
{
    private final Date sigTime, maximumExpectedTime;

    public SigningTimeVerificationException(
            Date sigTime,
            Date maximumExpectedTime)
    {
        this.sigTime = sigTime;
        this.maximumExpectedTime = maximumExpectedTime;
    }

    public Date getSigTime()
    {
        return sigTime;
    }

    public Date getMaximumExpectedTime()
    {
        return maximumExpectedTime;
    }

    @Override
    protected String getVerificationMessage()
    {
        DateFormat df = DateFormat.getDateTimeInstance();
        return String.format("Expected a signature time before %s but actual signature time is %s",
                df.format(maximumExpectedTime), df.format(sigTime));
    }

    @Override
    public String getPropertyName()
    {
        return SigningTimeProperty.PROP_NAME;
    }
}
