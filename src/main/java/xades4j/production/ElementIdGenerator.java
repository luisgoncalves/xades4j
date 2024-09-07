/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2024 Luis Goncalves.
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

package xades4j.production;

import java.util.UUID;

/**
 * Generates IDs for XML elements in a given signing operation.
 */
public interface ElementIdGenerator
{
    /**
     * Generate an ID for an XML element.
     *
     * @param namespace the element namespace
     * @param name      the element name
     * @return the ID
     */
    String generateId(String namespace, String name);

    /**
     * Gets a {@link ElementIdGenerator} that uses a UUID for each requested ID.
     */
    static ElementIdGenerator uuid()
    {
        return uuid(null, null);
    }

    /**
     * Gets a {@link ElementIdGenerator} that uses a UUID for each requested ID, optionally using a constant prefix
     * and/or suffix.
     *
     * @param prefix the ID prefix (may be null)
     * @param suffix the ID suffix (may be null)
     */
    static ElementIdGenerator uuid(String prefix, String suffix)
    {
        final String p = prefix == null ? "" : prefix;
        final String s = suffix == null ? "" : suffix;
        return (ns, n) -> p + UUID.randomUUID() + s;
    }
}
