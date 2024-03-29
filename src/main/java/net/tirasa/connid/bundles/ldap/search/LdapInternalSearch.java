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
import java.util.List;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import net.tirasa.connid.bundles.ldap.LdapConnection;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.common.StringUtil;

/**
 * A class to perform an LDAP search against a {@link LdapConnection}.
 *
 * @author Andrei Badea
 */
public class LdapInternalSearch {

    protected final LdapConnection conn;

    protected final String filter;

    protected final List<String> baseDNs;

    protected final LdapSearchStrategy strategy;

    protected final SearchControls controls;

    public LdapInternalSearch(
            final LdapConnection conn,
            final String filter,
            final List<String> baseDNs,
            final LdapSearchStrategy strategy,
            final SearchControls controls) {

        this.conn = conn;
        this.filter = StringUtil.isNotBlank(filter) ? filter : "(objectClass=*)";
        this.baseDNs = baseDNs;
        this.strategy = strategy;
        this.controls = controls;
    }

    public void execute(final LdapSearchResultsHandler handler) {
        try {
            strategy.doSearch(
                    conn.getInitialContext(),
                    baseDNs,
                    filter,
                    controls,
                    handler);
        } catch (IOException e) {
            throw new ConnectorException(e);
        } catch (NamingException e) {
            throw new ConnectorException(e);
        }
    }

    public static SearchControls createDefaultSearchControls() {
        SearchControls result = new SearchControls();
        result.setCountLimit(0);
        // Setting true to be consistent with the adapter. However, the
        // comment in the adapter that this flag causes the referrals to be
        // followed is wrong. Cf. http://java.sun.com/products/jndi/tutorial/ldap/misc/aliases.html.
        result.setDerefLinkFlag(true);
        result.setReturningObjFlag(false);
        result.setTimeLimit(0);
        return result;
    }
}
