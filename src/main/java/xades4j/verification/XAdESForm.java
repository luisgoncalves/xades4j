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
package xades4j.verification;

/**
 * The different XAdES signature forms.
 * @author Luís
 */
public enum XAdESForm
{
    BES("BES", "Basic electronic signature"),
    EPES("EPES", "Explicit policy electronic signature"),
    T("T", "Electronic signature with time"),
    C("C", "Electronic signature with complete validation data references"),
    X("X", "Extended signatures with time forms"),
    X_L("X-L", "Extended long electronic signatures with time"),
    A("A", "Archival electronic signatures");

    /**/
    private final String alias, fullName;

    private XAdESForm(String alias, String fullName)
    {
        this.alias = alias;
        this.fullName = fullName;
    }

    public String getFullName()
    {
        return fullName;
    }

    public boolean before(XAdESForm f)
    {
        return this.ordinal() < f.ordinal();
    }

    public boolean after(XAdESForm f)
    {
        return this.ordinal() > f.ordinal();
    }

    @Override
    public String toString()
    {
        return "XAdES-" + alias;
    }
}
