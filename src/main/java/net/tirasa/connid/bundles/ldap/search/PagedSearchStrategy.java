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
import java.util.Base64;
import java.util.List;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.OperationNotSupportedException;
import javax.naming.PartialResultException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.PagedResultsControl;
import javax.naming.ldap.PagedResultsResponseControl;
import javax.naming.ldap.SortControl;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.spi.SearchResultsHandler;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.SortKey;

public class PagedSearchStrategy extends LdapSearchStrategy {

    private static final Log LOG = Log.getLog(PagedSearchStrategy.class);

    protected final int pageSize;

    protected final int pagedResultsOffset;

    protected final String pagedResultsCookie;

    protected final SearchResultsHandler searchResultHandler;

    protected final SortKey[] sortKeys;

    public PagedSearchStrategy(final int pageSize, final String pagedResultsCookie, final Integer pagedResultsOffset,
            final SearchResultsHandler searchResultHandler, final SortKey[] sortKeys) {

        this.pageSize = pageSize;
        this.pagedResultsOffset = pagedResultsOffset == null ? 0 : pagedResultsOffset;
        this.pagedResultsCookie = pagedResultsCookie;
        this.searchResultHandler = searchResultHandler;
        this.sortKeys = sortKeys;
    }

    @Override
    public void doSearch(final LdapContext initCtx, final List<String> baseDNs, final String query,
            final SearchControls searchControls, final LdapSearchResultsHandler handler)
            throws IOException, NamingException {

        LOG.ok("Searching in {0} with filter {1} and {2}", baseDNs, query, searchControlsToString(searchControls));

        byte[] cookie = null;
        int context = 0;
        if (StringUtil.isNotBlank(pagedResultsCookie)) {
            // we need to determine which base context we're dealing with...
            // The cookie value is <base64 encoded LDAP cookie>:<index in baseDNs>
            String[] split = pagedResultsCookie.split(":", 2);
            // bit of sanity check...
            if (split.length == 2) {
                try {
                    cookie = Base64.getDecoder().decode(split[0]);
                } catch (RuntimeException e) {
                    throw new ConnectorException("PagedResultsCookie is not properly encoded", e);
                }
                context = Integer.valueOf(split[1]);
            } else {
                throw new ConnectorException("PagedResultsCookie is not properly formatted");
            }
        }

        LdapContext ctx = initCtx.newInstance(null);
        int remainingResults = -1;
        boolean allResultsReturned = true;
        try {
            boolean proceed = true;
            int records = 0;
            boolean needMore;
            do {
                SortControl sortControl = null;
                if (sortKeys != null && sortKeys.length > 0) {
                    javax.naming.ldap.SortKey[] skis = new javax.naming.ldap.SortKey[sortKeys.length];
                    for (int i = 0; i < sortKeys.length; i++) {
                        skis[i] = new javax.naming.ldap.SortKey(sortKeys[i].getField(), sortKeys[i].isAscendingOrder(),
                                null);
                    }
                    // We don't want to make this critical... better return unsorted results than nothing.
                    sortControl = new SortControl(skis, Control.NONCRITICAL);
                }
                if (sortControl == null) {
                    ctx.setRequestControls(new Control[] {
                        new PagedResultsControl(pageSize - records, cookie, Control.CRITICAL) });
                } else {
                    ctx.setRequestControls(new Control[] {
                        new PagedResultsControl(pageSize - records, cookie, Control.CRITICAL), sortControl
                    });
                }

                NamingEnumeration<SearchResult> results = ctx.search(baseDNs.get(context), query, searchControls);
                while (proceed && results.hasMore()) {
                    SearchResult result = results.next();
                    records++;
                    if (records > pagedResultsOffset) {
                        proceed = handler.handle(baseDNs.get(context), result);
                    }
                }
                if ((records < pageSize) && (context + 1 < baseDNs.size())) {
                    needMore = true;

                    context++;
                    cookie = null;
                } else {
                    needMore = false;

                    PagedResultsResponseControl pagedControl = getPagedControl(ctx.getResponseControls());
                    if (pagedControl != null) {
                        cookie = pagedControl.getCookie();
                        if (pagedControl.getResultSize() > 0) {
                            remainingResults = pagedControl.getResultSize();
                        }
                    }
                }

                results.close();
            } while (needMore);
        } catch (OperationNotSupportedException e) {
            LOG.ok("OperationNotSupportedException caught: {0}. Check the Cookie validity", e.getRemainingName());
            throw new ConnectorException("Operation Not Supported. Bad cookie");
        } catch (PartialResultException e) {
            LOG.ok("PartialResultException caught: {0}", e.getRemainingName());
            allResultsReturned = false;
        } finally {
            ctx.close();
        }

        String returnedCookie = null;
        if (cookie != null) {
            returnedCookie = Base64.getEncoder().encodeToString(cookie).concat(":" + context);
        }

        if (searchResultHandler != null) {
            searchResultHandler.handleResult(
                    new org.identityconnectors.framework.common.objects.SearchResult(
                            returnedCookie, remainingResults, allResultsReturned));
        }
    }

    protected PagedResultsResponseControl getPagedControl(final Control[] controls) {
        if (controls != null) {
            for (Control control : controls) {
                if (control instanceof PagedResultsResponseControl) {
                    return (PagedResultsResponseControl) control;
                }
            }
        }
        return null;
    }
}
