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
 * The {@code xades141:ArchiveTimeStamp} unsigned signature property. Used for the
 * XAdES-A form.
 * @author Luís
 */
public final class ArchiveTimeStampProperty extends UnsignedSignatureProperty
{
    public static final String PROP_NAME = "xadesv141:ArchiveTimeStamp";
    /**/
    private Date time;

    /**
     * Gets the time-stamp time after signature production or verification.
     * @return the time or {@code null} if the property wasn't part of a signature production
     */
    public Date getTime()
    {
        return time;
    }

    /**
     * Sets the time-stamp time. This is set during signature production so that
     * the time-stamp can be accessed afterwards.
     * @param time the time
     */
    public void setTime(Date time)
    {
        this.time = time;
    }

    @Override
    public String getName()
    {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
