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

import com.sun.jndi.ldap.ctl.VirtualListViewControl;
import com.sun.jndi.ldap.ctl.VirtualListViewResponseControl;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.SortControl;
import javax.naming.ldap.SortResponseControl;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;

public class VlvIndexSearchStrategy extends LdapSearchStrategy {

    private static Log LOG = Log.getLog(VlvIndexSearchStrategy.class);

    protected final String vlvIndexAttr;

    protected final int pageSize;

    protected int index;

    protected int lastListSize;

    protected byte[] cookie;

    public VlvIndexSearchStrategy(final String vlvSortAttr, final int pageSize) {
        this.vlvIndexAttr = StringUtil.isNotBlank(vlvSortAttr) ? vlvSortAttr : "uid";
        this.pageSize = pageSize;
    }

    @Override
    public void doSearch(final LdapContext initCtx, final List<String> baseDNs, final String query,
            final SearchControls searchControls, final LdapSearchResultsHandler handler)
            throws IOException, NamingException {

        LOG.ok("Searching in {0} with filter {1} and {2}", baseDNs, query, searchControlsToString(searchControls));

        Iterator<String> baseDNIter = baseDNs.iterator();
        boolean proceed = true;

        LdapContext ctx = initCtx.newInstance(null);
        try {
            while (baseDNIter.hasNext() && proceed) {
                proceed = searchBaseDN(ctx, baseDNIter.next(), query, searchControls, handler);
            }
        } finally {
            ctx.close();
        }
    }

    protected boolean searchBaseDN(final LdapContext ctx, final String baseDN, final String query,
            final SearchControls searchControls, final LdapSearchResultsHandler handler)
            throws IOException, NamingException {

        LOG.ok("Searching in {0}", baseDN);

        index = 1;
        lastListSize = 0;
        cookie = null;

        String lastResultName = null;

        for (;;) {
            SortControl sortControl = new SortControl(vlvIndexAttr, Control.CRITICAL);

            int afterCount = pageSize - 1;

            VirtualListViewControl vlvControl =
                    new VirtualListViewControl(index, lastListSize, 0, afterCount, Control.CRITICAL);
            vlvControl.setContextID(cookie);

            LOG.ok("New search: target = {0}, afterCount = {1}", index, afterCount);
            ctx.setRequestControls(new Control[] { sortControl, vlvControl });

            // Need to process the response controls, which are available after
            // all results have been processed, before sending anything to the caller
            // (because processing the response controls might throw exceptions that
            // invalidate anything we might have sent otherwise).
            // So storing the results before actually sending them to the handler.
            List<SearchResult> resultList = new ArrayList<SearchResult>(pageSize);

            NamingEnumeration<SearchResult> results = ctx.search(baseDN, query, searchControls);
            try {
                while (results.hasMore()) {
                    SearchResult result = results.next();

                    boolean overlap = false;
                    if (lastResultName != null) {
                        if (lastResultName.equals(result.getName())) {
                            LOG.warn("Working around rounding error overlap at index " + index);
                            overlap = true;
                        }
                        lastResultName = null;
                    }

                    if (!overlap) {
                        resultList.add(result);
                    }
                }
            } finally {
                results.close();
            }

            processResponseControls(ctx.getResponseControls());

            SearchResult result = null;
            Iterator<SearchResult> resultIter = resultList.iterator();
            while (resultIter.hasNext()) {
                result = resultIter.next();
                index++;
                if (!handler.handle(baseDN, result)) {
                    return false;
                }
            }
            if (result != null) {
                lastResultName = result.getName();
            }

            if (index > lastListSize) {
                break;
            }

            // DSEE seems to only have a single VLV index (although it claims to support more).
            // It returns at the server content count the sum of sizes of all indexes,
            // but it only returns the entries in the base context we are asking for.
            // So, in this case, index will never reach lastListSize. To avoid an infinite loop,
            // ending search if we received no results in the last iteration.
            if (resultList.isEmpty()) {
                LOG.warn("Ending search because received no results");
                break;
            }
        }
        return true;
    }

    protected void processResponseControls(Control[] controls) throws NamingException {
        if (controls != null) {
            for (Control control : controls) {
                if (control instanceof SortResponseControl) {
                    SortResponseControl sortControl = (SortResponseControl) control;
                    if (!sortControl.isSorted() || (sortControl.getResultCode() != 0)) {
                        throw sortControl.getException();
                    }
                }
                if (control instanceof VirtualListViewResponseControl) {
                    VirtualListViewResponseControl vlvControl = (VirtualListViewResponseControl) control;
                    if (vlvControl.getResultCode() == 0) {
                        lastListSize = vlvControl.getListSize();
                        cookie = vlvControl.getContextID();
                        LOG.ok("Response control: lastListSize = {0}", lastListSize);
                    } else {
                        throw vlvControl.getException();
                    }
                }
            }
        }
    }
}
