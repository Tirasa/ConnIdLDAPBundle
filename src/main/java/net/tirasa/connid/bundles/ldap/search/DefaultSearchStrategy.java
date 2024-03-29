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

import java.util.Iterator;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;

import org.identityconnectors.common.logging.Log;

public class DefaultSearchStrategy extends LdapSearchStrategy {

    private static final Log LOG = Log.getLog(DefaultSearchStrategy.class);

    protected final boolean ignoreNonExistingBaseDNs;

    public DefaultSearchStrategy(boolean ignoreNonExistingBaseDNs) {
        this.ignoreNonExistingBaseDNs = ignoreNonExistingBaseDNs;
    }

    @Override
    public void doSearch(LdapContext initCtx, List<String> baseDNs, String query, SearchControls searchControls,
            LdapSearchResultsHandler handler) throws NamingException {

        LOG.ok("Searching in {0} with filter {1} and {2}", baseDNs, query, searchControlsToString(searchControls));

        Iterator<String> baseDNIter = baseDNs.iterator();
        boolean proceed = true;

        while (baseDNIter.hasNext() && proceed) {
            String baseDN = baseDNIter.next();

            NamingEnumeration<SearchResult> results;
            try {
                results = initCtx.search(baseDN, query, searchControls);
            } catch (NameNotFoundException e) {
                if (!ignoreNonExistingBaseDNs) {
                    throw e;
                }
                LOG.warn(e, null);
                continue;
            } catch (InvalidNameException e) {
                if (!ignoreNonExistingBaseDNs) {
                    throw e;
                }
                LOG.warn(e, null);
                continue;
            }
            try {
                while (proceed && results.hasMore()) {
                    proceed = handler.handle(baseDN, results.next());
                }
            } finally {
                results.close();
            }
        }
    }

}
