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
package xades4j.properties;

import java.util.Date;

/**
 * The {@code SigAndRefsTimeStamp} element is an unsigned property qualifying
 * the signature.
 * <p>
 * This property contains a time-stamp token that covers the following data
 * objects: {@code ds:SignatureValue} element, all present {@code SignatureTimeStamp}
 * elements, {@code CompleteCertificateRefs}, {@code CompleteRevocationRefs}, and
 * when present, {@code AttributeCertificateRefs} and {@code AttributeRevocationRefs}.
 * @author Luís
 */
public final class SigAndRefsTimeStampProperty extends UnsignedSignatureProperty
{
    public static final String PROP_NAME = "SigAndRefsTimeStamp";
    /**/
    private Date time;

    /**
     * Gets the time-stamp time.
     * @return the time or {@code null} if the property hasn't been processed in signature production or verification
     */
    public Date getTime()
    {
        return time;
    }

    public void setTime(Date time)
    {
        this.time = time;
    }

    @Override
    public String getName()
    {
        return PROP_NAME;
    }
}
