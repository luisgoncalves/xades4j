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
