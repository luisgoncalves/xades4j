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

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.GregorianCalendar;

/**
 * The {@code SigningTime} property specifies the time at which the signer
 * (purportedly) performed the signing process. Extended for working with
 * different time formats.
 * <p>
 * This is an optional signed property that qualifies the whole signature. There
 * is at most one occurence of this property in the signature.
 *
 * @see xades4j.providers.SignaturePropertiesProvider
 * @author Luís
 * @author Umut
 */
public final class SigningTimeProperty extends SignedSignatureProperty
{
    public static final String PROP_NAME = "SigningTime";
    /**/
    private final Calendar signingTime;
    private final SimpleDateFormat simpleDateFormatter;

    public SigningTimeProperty()
    {
        this.signingTime = new GregorianCalendar();
        this.simpleDateFormatter = null;
    }

    public SigningTimeProperty(Calendar signingTime)
    {
        this.signingTime = signingTime;
        this.simpleDateFormatter = null;
    }

    public SigningTimeProperty(Calendar signingTime, SimpleDateFormat simpleDateFormatter) {
        this.signingTime = signingTime;
        this.simpleDateFormatter = simpleDateFormatter;
    }

    public Calendar getSigningTime()
    {
        return signingTime;
    }

    public SimpleDateFormat getDateFormat() {
        return simpleDateFormatter;
    }

    @Override
    public String getName()
    {
        return PROP_NAME;
    }
}
