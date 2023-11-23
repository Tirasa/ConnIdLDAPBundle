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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import net.tirasa.connid.bundles.ldap.LdapConnection;
import net.tirasa.connid.bundles.ldap.commons.LdapEntry;
import net.tirasa.connid.bundles.ldap.commons.LdapUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;

/**
 * Helper methods for searching. The "get" methods throw an exception when
 * nothing is found; the "find" methods return null or an empty result.
 *
 * @author Andrei Badea
 */
public final class LdapSearches {

    // TODO: when more than one base DN is specified in the configuration,
    // some searches could be faster by searching the entry under all naming
    // contexts on the server and then checking that the entry is really under one of the
    // configured base DNs.
    private static final Log LOG = Log.getLog(LdapSearches.class);

    private LdapSearches() {
        // private constructor for static utility class
    }

    /**
     * Returns the DN of the entry identified by the given Uid. Throws <code>UnknownUidException</code>
     * if such an entry does not exists.
     */
    public static String getEntryDN(LdapConnection conn, ObjectClass oclass, Uid uid) {
        return findEntryDN(conn, oclass, uid, true, false);
    }

    public static String getEntryDN(LdapConnection conn, ObjectClass oclass, Uid uid,
            boolean ignoreCustomAnyObjectConfig) {
        return findEntryDN(conn, oclass, uid, true, ignoreCustomAnyObjectConfig);
    }

    /**
     * Returns the DN of the entry identified by the given Uid. May throw <code>UnknownUidException</code>
     * if such an entry does not exists, but not necessarily.
     */
    public static String findEntryDN(LdapConnection conn, ObjectClass oclass, Uid uid) {
        return findEntryDN(conn, oclass, uid, false, false);
    }

    public static String findEntryDN(
            LdapConnection conn,
            ObjectClass oclass,
            Uid uid,
            boolean ignoreCustomAnyObjectConfig) {

        return findEntryDN(conn, oclass, uid, false, ignoreCustomAnyObjectConfig);
    }

    /**
     * Finds the DN of the entry corresponding to the given Uid. If the <code>check</code>
     * parameter is false, the method will take the quickest path to return the DN, but will not necessarily
     * check that an entry with the returned DN exists. If the <code>check</code> parameter is false,
     * the method will throw a <code>UnknownUidException</code> if the entry identified
     * by the Uid does not exist.
     */
    private static String findEntryDN(
            LdapConnection conn,
            ObjectClass oclass,
            Uid uid,
            boolean check,
            boolean ignoreCustomAnyObjectConfig) {

        LOG.ok("Searching for object {0} of class {1}", uid.getUidValue(), oclass.getObjectClassValue());

        LdapFilter ldapFilter;

        // If the Uid is actually the entry DN, we do not need to do a search do find the entry DN.
        String uidAttr = conn.getSchemaMapping().getLdapUidAttribute(oclass);
        if (LdapEntry.isDNAttribute(uidAttr)) {
            if (check) {
                // We'll do a search in order to check that the entry with that DN exists.
                ldapFilter = LdapFilter.forEntryDN(uid.getUidValue());
            } else {
                // Short path. The Uid is the entry DN, and we do not need to check it,
                // so we can return it right away.
                return uid.getUidValue();
            }
        } else {
            EqualsFilter filter = (EqualsFilter) FilterBuilder.equalTo(uid);
            ldapFilter = new LdapFilterTranslator(conn.getSchemaMapping(), oclass).
                    createEqualsExpression(filter, false);
        }
        assert ldapFilter != null;

        OperationOptionsBuilder builder = new OperationOptionsBuilder();
        builder.setAttributesToGet(conn.getConfiguration().getDnAttribute());
        builder.setOption(LdapSearch.OP_IGNORE_CUSTOM_ANY_OBJECT_CONFIG, ignoreCustomAnyObjectConfig);

        LdapSearch search = new LdapSearch(conn, oclass, ldapFilter, null, builder.build());
        ConnectorObject object = search.getSingleResult();
        if (object != null) {
            return AttributeUtil.getStringValue(object.getAttributeByName(conn.getConfiguration().getDnAttribute()));
        }
        throw new UnknownUidException(uid, oclass);
    }

    public static List<ConnectorObject> findObjects(
            LdapConnection conn, ObjectClass oclass, String baseDN, Attribute attr, String... attrsToGet) {

        LOG.ok("Searching for object with attribute {0} of class {1} in {2}",
                attr, oclass.getObjectClassValue(), baseDN);

        final List<ConnectorObject> result = new ArrayList<>();

        EqualsFilter filter = (EqualsFilter) FilterBuilder.equalTo(attr);
        LdapFilter ldapFilter = new LdapFilterTranslator(conn.getSchemaMapping(), oclass).
                createEqualsExpression(filter, false);

        OperationOptionsBuilder builder = new OperationOptionsBuilder();
        builder.setAttributesToGet(attrsToGet);

        LdapSearch search = new LdapSearch(conn, oclass, ldapFilter, new ResultsHandler() {

            @Override
            public boolean handle(final ConnectorObject object) {
                result.add(object);
                return true;
            }
        }, builder.build(), baseDN);
        search.execute();
        return result;
    }

    public static ConnectorObject findObject(
            final LdapConnection conn,
            final ObjectClass oclass,
            final LdapFilter filter,
            final String... attrsToGet) {

        LOG.ok("Searching for object of class {0} with filter {1}",
                oclass.getObjectClassValue(), filter);

        OperationOptionsBuilder builder = new OperationOptionsBuilder();
        builder.setAttributesToGet(attrsToGet);

        LdapSearch search = new LdapSearch(conn, oclass, filter, null, builder.build());
        return search.getSingleResult();
    }

    public static LdapEntry getEntry(LdapConnection conn, LdapName entryDN, String... ldapAttrsToGet) {
        LOG.ok("Searching for entry {0}", entryDN);

        final List<LdapEntry> result = new ArrayList<>();
        if (!LdapUtil.isUnderContexts(entryDN, conn.getConfiguration().
                getBaseContextsAsLdapNames())) {
            return null;
        }

        SearchControls controls = LdapInternalSearch.createDefaultSearchControls();
        controls.setSearchScope(SearchControls.OBJECT_SCOPE);
        controls.setReturningAttributes(ldapAttrsToGet);
        LdapInternalSearch search = new LdapInternalSearch(conn, null,
                Collections.singletonList(entryDN.toString()),
                conn.getConfiguration().newDefaultSearchStrategy(true), controls);
        search.execute(new LdapSearchResultsHandler() {

            @Override
            public boolean handle(String baseDN, SearchResult searchResult) {
                result.add(LdapEntry.create(baseDN, searchResult));
                return false;
            }
        });
        if (!result.isEmpty()) {
            return result.get(0);
        }
        throw new ConnectorException(conn.format("entryNotFound", null, entryDN));
    }

    public static void findEntries(
            final LdapSearchResultsHandler handler, final LdapConnection conn, final String filter,
            final String... ldapAttrsToGet) {

        LOG.ok("Searching for entries matching {0}", filter);

        List<String> baseDNs = Arrays.asList(conn.getConfiguration().getBaseContexts());
        SearchControls controls = LdapInternalSearch.createDefaultSearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(ldapAttrsToGet);
        LdapInternalSearch search = new LdapInternalSearch(
                conn, filter, baseDNs, conn.getConfiguration().newDefaultSearchStrategy(false), controls);
        search.execute(handler);
    }
}
