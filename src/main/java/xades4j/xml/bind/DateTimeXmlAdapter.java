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
package xades4j.xml.bind;

import java.util.Calendar;
import javax.xml.bind.annotation.adapters.XmlAdapter;
import xades4j.properties.SigningTimeProperty;

/**
 *
 * @author Luís
 */
public class DateTimeXmlAdapter extends XmlAdapter<String, SigningTimeProperty>
{
    @Override
    public SigningTimeProperty unmarshal(String value)
    {
        return new SigningTimeProperty(javax.xml.bind.DatatypeConverter.parseDateTime(value));
    }

    @Override
    public String marshal(SigningTimeProperty value)
    {
        if (value == null)
            return null;
        if (value.getDateFormat() != null) {
            return value.getDateFormat().format(value.getSigningTime().getTime());
        } else {
            return (javax.xml.bind.DatatypeConverter.printDateTime(value.getSigningTime()));
        }
    }
}
