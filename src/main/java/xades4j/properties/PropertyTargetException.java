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

/**
 * Indicates that a property couldn't be added to a target, such as a data object
 * description.
 * @author Luís
 */
public class PropertyTargetException extends IllegalStateException {

    /**
     * Creates a new instance of <code>PropertyTargetException</code> without detail message.
     */
    public PropertyTargetException() {
    }


    /**
     * Constructs an instance of <code>PropertyTargetException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public PropertyTargetException(String msg) {
        super(msg);
    }
}
