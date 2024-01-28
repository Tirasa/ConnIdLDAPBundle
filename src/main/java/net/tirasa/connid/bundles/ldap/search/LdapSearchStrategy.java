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
package net.tirasa.connid.bundles.ldap.search;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.LdapContext;

public abstract class LdapSearchStrategy {

    public abstract void doSearch(
            final LdapContext initCtx,
            final List<String> baseDNs,
            final String query,
            final SearchControls searchControls,
            final LdapSearchResultsHandler handler)
            throws IOException, NamingException;

    protected static String searchControlsToString(final SearchControls controls) {
        StringBuilder builder = new StringBuilder();

        builder.append("SearchControls: {returningAttributes=");
        String[] attrs = controls.getReturningAttributes();

        builder.append(attrs == null ? "null" : Arrays.asList(attrs));

        builder.append(", scope=");
        switch (controls.getSearchScope()) {
            case SearchControls.OBJECT_SCOPE:
                builder.append("OBJECT");
                break;

            case SearchControls.ONELEVEL_SCOPE:
                builder.append("ONELEVEL");
                break;

            case SearchControls.SUBTREE_SCOPE:
            default:
                builder.append("SUBTREE");
        }

        builder.append('}');
        return builder.toString();
    }
}
