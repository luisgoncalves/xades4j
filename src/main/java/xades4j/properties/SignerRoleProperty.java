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

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Represents the {@code SingerRole} signed signature property. A XAdES signature
 * has at most one {@code SingerRole} property.
 * <p>
 * This property is added to the signature through {@link xades4j.providers.SignaturePropertiesProvider}.
 * <p>
 * <b>Limitation</b>: only claimed roles are supported.
 * @author Luís
 */
public final class SignerRoleProperty extends SignedSignatureProperty
{
    public static final String PROP_NAME = "SignerRole";
    private final Set<String> claimedRoles;

    public SignerRoleProperty()
    {
        this.claimedRoles = new HashSet<String>();
    }

    public SignerRoleProperty(String... claimedRoles)
    {
        this();
        for (String role : claimedRoles)
        {
            this.claimedRoles.add(role);
        }
    }

    public SignerRoleProperty(Collection<String> claimedRoles)
    {
        this();
        for (String role : claimedRoles)
        {
            this.claimedRoles.add(role);
        }
    }

    public SignerRoleProperty withClaimedRole(String role)
    {
        if (role != null)
            this.claimedRoles.add(role);
        return this;
    }

    public Collection<String> getClaimedRoles()
    {
        return claimedRoles;
    }

    @Override
    public String getName()
    {
        return PROP_NAME;
    }
}
