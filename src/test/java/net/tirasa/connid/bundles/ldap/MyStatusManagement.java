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
 * http://opensource.org/licenses/cddl1.php
 * See the License for the specific language governing permissions and limitations
 * under the License.
 * 
 * When distributing the Covered Code, include this CDDL Header Notice in each file
 * and include the License file at http://opensource.org/licenses/cddl1.php.
 * If applicable, add the following below this CDDL Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 * ====================
 * Portions Copyrighted 2011 ConnId.
 */
package net.tirasa.connid.bundles.ldap;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import net.tirasa.connid.bundles.ldap.commons.StatusManagement;

public class MyStatusManagement extends StatusManagement {

    @Override
    public void setStatus(
            final boolean status,
            final Attributes attributes,
            final List<String> posixGroups,
            final List<String> ldapGroups) {
        Attribute description = attributes.get("description");
        if (description == null) {
            description = new BasicAttribute("description");
            attributes.put(description);
        }

        // set 0 to disable and 1 to enable
        description.add(status ? "1" : "0");
    }

    @Override
    public Boolean getStatus(
            final Attributes attributes,
            final List<String> posixGroups,
            final List<String> ldapGroups) {

        Boolean status = null;

        Attribute description = attributes.get("description");
        if (description != null) {
            try {
                Object value = description.get();
                if (value != null) {
                    status = "1".equals(value.toString());
                }
            } catch (NamingException ignore) {
                // ignore exception
            }
        }

        return status;
    }

    @Override
    public Set<String> getOperationalAttributes() {
        return Collections.singleton("description");
    }
}
