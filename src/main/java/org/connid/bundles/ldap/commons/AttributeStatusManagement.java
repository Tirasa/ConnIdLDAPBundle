/**
 * ====================
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright 2008-2009 Sun Microsystems, Inc. All rights reserved.
 * Copyright 2011-2013 Tirasa. All rights reserved.
 *
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License("CDDL") (the "License"). You may not use this file
 * except in compliance with the License.
 *
 * You can obtain a copy of the License at https://oss.oracle.com/licenses/CDDL
 * See the License for the specific language governing permissions and limitations
 * under the License.
 *
 * When distributing the Covered Code, include this CDDL Header Notice in each file
 * and include the License file at https://oss.oracle.com/licenses/CDDL.
 * If applicable, add the following below this CDDL Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 * ====================
 */
package org.connid.bundles.ldap.commons;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;

public class AttributeStatusManagement extends StatusManagement {

    protected static final String ATTR_NAME = "description";

    protected static final String ATTR_VALUE_ACTIVE = "Active";

    protected static final String ATTR_VALUE_INACTIVE = "Inactive";

    @Override
    public void setStatus(boolean status, final Attributes attributes,
            final List<String> posixGroups, final List<String> ldapGroups) {

        Attribute description = attributes.get(ATTR_NAME);
        if (description == null) {
            description = new BasicAttribute(ATTR_NAME);
            attributes.put(description);
        }

        description.add(status ? ATTR_VALUE_ACTIVE : ATTR_VALUE_INACTIVE);
    }

    @Override
    public Boolean getStatus(final Attributes attributes,
            final List<String> posixGroups, final List<String> ldapGroups) {

        Boolean status = null;

        Attribute description = attributes.get(ATTR_NAME);
        if (description != null) {
            try {
                Object value = description.get();
                if (value != null) {
                    status = ATTR_VALUE_ACTIVE.equals(value.toString());
                }
            } catch (NamingException ignore) {
                // ignore exception
            }
        }

        return status;
    }

    @Override
    public Set<String> getOperationalAttributes() {
        return Collections.singleton(ATTR_NAME);

    }
}
