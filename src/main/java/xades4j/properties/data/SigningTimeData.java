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
package xades4j.properties.data;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import xades4j.properties.SigningTimeProperty;

/**
 *
 * @author Luís
 */
public final class SigningTimeData implements PropertyDataObject
{
    private final Calendar signingTime;
    private final SigningTimeProperty signingTimeProperty;

    public SigningTimeData(Calendar signingTime)
    {
        this.signingTime = signingTime;
        this.signingTimeProperty = new SigningTimeProperty(signingTime);
    }

    public SigningTimeData(SigningTimeProperty signingTimeProperty) {
        this.signingTime = signingTimeProperty.getSigningTime();
        this.signingTimeProperty = signingTimeProperty;
    }
    /**
     * Get the value of signingTime
     *
     * @return the value of signingTime
     */
    public Calendar getSigningTime()
    {
        return signingTime;
    }

    public SigningTimeProperty getSigningTimeProperty() {
        return signingTimeProperty;
    }
}
