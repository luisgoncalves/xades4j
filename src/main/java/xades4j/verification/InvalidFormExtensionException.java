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
package xades4j.verification;

import xades4j.XAdES4jException;

/**
 * Thrown during signature verification (with form extension) when the form transition
 * is invalid. For instance, XAdES-BES -> XAdES-X is invalid.
 * @see XadesVerifier
 * @author Luís
 */
public class InvalidFormExtensionException extends XAdES4jException
{
    private final XAdESForm actualForm, finalForm;

    public InvalidFormExtensionException(
            XAdESForm actualForm,
            XAdESForm finalForm)
    {
        this.actualForm = actualForm;
        this.finalForm = finalForm;
    }

    /**
     * Gets the form of the signature that was being extended.
     * @return the form
     */
    public XAdESForm getActualForm()
    {
        return actualForm;
    }

    /**
     * Gets the desired signature form.
     * @return the form
     */
    public XAdESForm getFinalForm()
    {
        return finalForm;
    }

    @Override
    public String getMessage()
    {
        return String.format("Invalid form transition: %s to %s", this.actualForm, this.finalForm);
    }
}
