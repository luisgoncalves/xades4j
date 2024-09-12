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
 * A factory of {@link ElementIdGenerator}.
 */
public interface ElementIdGeneratorFactory
{
    /**
     * Create a new {@link ElementIdGenerator}. This method is invoked once for each signing operation and the returned
     * instance is used to obtain element IDs during that operation. This allows for scenarios where all the element IDs
     * share a common base.
     *
     * @return the ID generator
     */
    ElementIdGenerator create();

    /**
     * Gets a {@link ElementIdGeneratorFactory} that uses a UUID for each requested ID.
     */
    static ElementIdGeneratorFactory uuid()
    {
        return ElementIdGenerator::uuid;
    }

    /**
     * Gets a {@link ElementIdGeneratorFactory} that uses a UUID for each requested ID, optionally using a constant
     * prefix and/or suffix.
     *
     * @param prefix the ID prefix (may be null)
     * @param suffix the ID suffix (may be null)
     */
    static ElementIdGeneratorFactory uuid(String prefix, String suffix)
    {
        return () -> ElementIdGenerator.uuid(prefix, suffix);
    }
}
