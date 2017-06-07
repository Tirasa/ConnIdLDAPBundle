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

import java.util.List;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import org.identityconnectors.common.logging.Log;

/**
 * Uses the <tt>nsAccountLock</tt> attribute to implement enable/disable.
 *
 * Setting the attribute nsAccountLock to true will disable a users account and prevent
 * them from binding to the directory.
 */
public class NSStatusManagement extends AttributeStatusManagement {

    private static final Log LOG = Log.getLog(NSStatusManagement.class);

    @Override
    protected String getStatusAttrName() {
        return "nsAccountLock";
    }

    @Override
    protected String getStatusAttrActiveValue() {
        return "false";
    }

    @Override
    protected String getStatusAttrInactiveValue() {
        return "true";
    }

    @Override
    public void setStatus(final boolean status, final Attributes attributes,
            final List<String> posixGroups, final List<String> ldapGroups) {

        LOG.ok("Calling setStatus {0}", status);

        Object value = status ? getStatusAttrActiveValue() : getStatusAttrInactiveValue();
        attributes.remove(getStatusAttrName());
        attributes.put(getStatusAttrName(), value);
    }

    @Override
    public Boolean getStatus(final Attributes attributes,
            final List<String> posixGroups, final List<String> ldapGroups) {

        Boolean status = Boolean.TRUE;

        final Attribute attr = attributes.get(getStatusAttrName());
        if (attr != null) {
            try {
                Object value = attr.get();
                if (value != null) {
                    status ^= getStatusAttrInactiveValue().equalsIgnoreCase(value.toString());
                }
            } catch (NamingException ignore) {
                status = null;
            }
        }

        LOG.ok("Returning getStatus {0}", status);
        return status;
    }
}
