/*
 * ====================
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 * 
 * Copyright 2008-2009 Sun Microsystems, Inc. All rights reserved.     
 * 
 * The contents of this file are subject to the terms of the Common Development 
 * and Distribution License("CDDL") (the "License").  You may not use this file 
 * except in compliance with the License.
 * 
 * You can obtain a copy of the License at 
 * http://IdentityConnectors.dev.java.net/legal/license.txt
 * See the License for the specific language governing permissions and limitations 
 * under the License. 
 * 
 * When distributing the Covered Code, include this CDDL Header Notice in each file
 * and include the License file at identityconnectors/legal/license.txt.
 * If applicable, add the following below this CDDL Header, with the fields 
 * enclosed by brackets [] replaced by your own identifying information: 
 * "Portions Copyrighted [year] [name of copyright owner]"
 * ====================
 */
package org.identityconnectors.ldap.commons;

import java.util.List;
import java.util.Set;
import javax.naming.directory.Attributes;

public abstract class StatusManagement {

    private static StatusManagement instance = null;

    /**
     * Implements this method to alter information given by input parameters in 
     * order to implement a custom enable/disable behaviour.
     * @param attributes entity ldap attributes.
     * @param posixGroups entity ldap groups.
     * @param ldapGroups  entity posix groups.
     */
    public abstract void setStatus(
            final boolean status,
            final Attributes attributes,
            final List<String> posixGroups,
            final List<String> ldapGroups);

    /**
     * Implement this method to retrieve user status from the given parameters.
     * @param attributes entity ldap attributes.
     * @param posixGroups entity posix groups.
     * @param ldapGroups entity ldap groups.
     * @return TRUE if users is enable, FALS if disabled, null for no status found.
     */
    public abstract Boolean getStatus(
            final Attributes attributes,
            final List<String> posixGroups,
            final List<String> ldapGroups);

    /**
     * Provide all the ldap attributes needed to know the entity status.
     * @return set of ldap attributes to be added to the set of all the 
     * attributes to get during searches.
     */
    public abstract Set<String> getOperationalAttributes();

    public static StatusManagement getInstance(String c) {

        if (instance == null || !instance.getClass().getName().equals(c)) {
            if (c != null && !c.isEmpty()) {
                try {
                    instance = (StatusManagement) Class.forName(c).newInstance();
                } catch (Exception e) {
                    instance = new DefaultStatusManagement();
                }
            } else {
                instance = new DefaultStatusManagement();
            }
        }

        return instance;
    }
}
