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
 * Utility methods for strings.
 * @author Luís
 */
public class StringUtils
{
    public static boolean isNullOrEmptyString(String s)
    {
        return null == s || s.isEmpty();
    }

    public static boolean allNullOrEmptyStrings(String... srts)
    {
        for (int i = 0; i < srts.length; i++)
        {
            if (!isNullOrEmptyString(srts[i]))
                return false;
        }
        return true;
    }

    public static boolean differentStringsIfNotNullNorEmpty(String str1, String str2)
    {
        return str1 != null && str2 != null &&
                !str1.isEmpty() && !str2.isEmpty() &&
                !str1.equals(str2);
    }
}
