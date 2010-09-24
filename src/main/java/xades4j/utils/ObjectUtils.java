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
package xades4j.utils;

/**
 * Utility methods for objects.
 * @author Luís
 */
public class ObjectUtils
{
    /**
     * Indicates whether all the objects are {@code null}.
     * @param objs the set of objects to be checked
     * @return {@code true} if all the objects are {@code null}
     */
    public static boolean allNull(Object... objs)
    {
        for (int i = 0; i < objs.length; i++)
        {
            if (null != objs[i])
                return false;

        }
        return true;
    }

    /**
     * Indicates whether any of the objects are {@code null}.
     * @param objs the set of objects to be checked
     * @return {@code true} if at least one object is {@code null}
     */
    public static boolean anyNull(Object... objs)
    {
        for (int i = 0; i < objs.length; i++)
        {
            if (null == objs[i])
                return true;
        }
        return false;
    }
}
