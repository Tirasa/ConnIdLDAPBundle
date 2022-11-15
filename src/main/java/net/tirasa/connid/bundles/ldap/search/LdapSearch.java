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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.PagedResultsControl;
import net.tirasa.connid.bundles.ldap.LdapConnection;
import net.tirasa.connid.bundles.ldap.commons.GroupHelper;
import net.tirasa.connid.bundles.ldap.commons.LdapConstants;
import net.tirasa.connid.bundles.ldap.commons.LdapEntry;
import net.tirasa.connid.bundles.ldap.commons.LdapUtil;
import net.tirasa.connid.bundles.ldap.commons.StatusManagement;
import net.tirasa.connid.bundles.ldap.schema.LdapSchemaMapping;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.QualifiedUid;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.spi.SearchResultsHandler;

/**
 * A class to perform an LDAP search against a {@link LdapConnection}.
 *
 * @author Andrei Badea
 */
public class LdapSearch {

    private static final Log LOG = Log.getLog(LdapSearch.class);

    private final LdapConnection conn;

    private final ObjectClass oclass;

    private final LdapFilter filter;

    private final OperationOptions options;

    private final GroupHelper groupHelper;

    private final String[] baseDNs;

    private final ResultsHandler handler;

    public static Set<String> getAttributesReturnedByDefault(final LdapConnection conn, final ObjectClass oclass) {
        if (oclass.equals(LdapSchemaMapping.ANY_OBJECT_CLASS)) {
            return CollectionUtil.newSet(Name.NAME);
        }
        Set<String> result = CollectionUtil.newCaseInsensitiveSet();
        ObjectClassInfo oci = conn.getSchemaMapping().schema().findObjectClassInfo(oclass.getObjectClassValue());
        if (oci != null) {
            for (AttributeInfo info : oci.getAttributeInfo()) {
                if (info.isReturnedByDefault()) {
                    result.add(info.getName());
                }
            }
        }
        return result;
    }

    public LdapSearch(
            final LdapConnection conn,
            final ObjectClass oclass,
            final LdapFilter filter,
            final ResultsHandler handler,
            final OperationOptions options) {

        this(conn, oclass, filter, handler, options, conn.getConfiguration().getBaseContexts());
    }

    public LdapSearch(
            final LdapConnection conn,
            final ObjectClass oclass,
            final LdapFilter filter,
            final ResultsHandler handler,
            final OperationOptions options,
            final String... baseDNs) {

        this.conn = conn;
        this.oclass = oclass;
        this.filter = filter;
        this.options = options;
        this.baseDNs = baseDNs;
        this.groupHelper = new GroupHelper(conn);
        this.handler = handler;
    }

    /**
     * Performs the search and passes the resulting {@link ConnectorObject}s to the given handler.
     */
    public final void execute() {
        final String[] attrsToGetOption = options.getAttributesToGet();
        final Set<String> attrsToGet = getAttributesToGet(attrsToGetOption);

        final LdapInternalSearch search = getInternalSearch(attrsToGet);

        search.execute(new LdapSearchResultsHandler() {

            @Override
            public boolean handle(final String baseDN, final SearchResult result) throws NamingException {
                return handler.handle(createConnectorObject(baseDN, result, attrsToGet, attrsToGetOption != null));
            }
        });
    }

    /**
     * Executes the query against all configured base DNs and returns the first {@link ConnectorObject} or {@code null}.
     *
     * @return the first {@link ConnectorObject} or {@code null}
     */
    public final ConnectorObject getSingleResult() {
        final String[] attrsToGetOption = options.getAttributesToGet();
        final Set<String> attrsToGet = getAttributesToGet(attrsToGetOption);
        final ConnectorObject[] results = new ConnectorObject[] { null };

        final LdapInternalSearch search = getInternalSearch(attrsToGet);

        search.execute(new LdapSearchResultsHandler() {

            @Override
            public boolean handle(final String baseDN, final SearchResult result) throws NamingException {
                results[0] = createConnectorObject(baseDN, result, attrsToGet, attrsToGetOption != null);
                return false;
            }
        });

        return results[0];
    }

    private LdapInternalSearch getInternalSearch(final Set<String> attrsToGet) {
        // This is a bit tricky. If the LdapFilter has an entry DN,
        // we only need to look at that entry and check whether it matches
        // the native filter. Moreover, when looking at the entry DN
        // we must not throw exceptions if the entry DN does not exist or is
        // not valid -- just as no exceptions are thrown when the native
        // filter doesn't return any values.
        //
        // In the simple case when the LdapFilter has no entryDN, we
        // will just search over our base DNs looking for entries
        // matching the native filter.
        LdapSearchStrategy strategy;
        List<String> dns;
        int searchScope;

        String filterEntryDN = filter == null ? null : filter.getEntryDN();
        if (filterEntryDN == null) {
            strategy = getSearchStrategy();
            dns = getBaseDNs();
            searchScope = getLdapSearchScope();
        } else {
            // Would be good to check that filterEntryDN is under the configured base contexts.
            // However, the adapter is likely to pass entries outside the base contexts,
            // so not checking in order to be on the safe side.
            strategy = conn.getConfiguration().newDefaultSearchStrategy(true);
            dns = Collections.singletonList(filterEntryDN);
            searchScope = SearchControls.OBJECT_SCOPE;
        }

        SearchControls controls = LdapInternalSearch.createDefaultSearchControls();
        Set<String> ldapAttrsToGet = getLdapAttributesToGet(attrsToGet);

        controls.setReturningAttributes(ldapAttrsToGet.toArray(new String[ldapAttrsToGet.size()]));

        controls.setSearchScope(searchScope);

        String optionsFilter = LdapConstants.getSearchFilter(options);
        String searchFilter = null;
        if (oclass.equals(ObjectClass.ACCOUNT)) {
            searchFilter = conn.getConfiguration().getAccountSearchFilter();
        } else if (oclass.equals(ObjectClass.GROUP)) {
            searchFilter = conn.getConfiguration().getGroupSearchFilter();
        }
        String nativeFilter = filter == null ? null : filter.getNativeFilter();
        return new LdapInternalSearch(conn,
                getSearchFilter(optionsFilter, nativeFilter, searchFilter),
                dns, strategy, controls);
    }

    private Set<String> getLdapAttributesToGet(final Set<String> attrsToGet) {
        final Set<String> cleanAttrsToGet = CollectionUtil.newCaseInsensitiveSet();

        cleanAttrsToGet.addAll(attrsToGet);
        cleanAttrsToGet.remove(LdapConstants.LDAP_GROUPS_NAME);

        final boolean posixGroups = cleanAttrsToGet.remove(LdapConstants.POSIX_GROUPS_NAME);

        final Set<String> result = conn.getSchemaMapping().getLdapAttributes(oclass, cleanAttrsToGet, true);

        if (posixGroups) {
            result.add(GroupHelper.getPosixRefAttribute());
        }

        // Add attributes needed to define the entity status.
        // This attributes won't be attached to the connector object.
        result.addAll(StatusManagement.getInstance(
                conn.getConfiguration().getStatusManagementClass()).getOperationalAttributes());

        // For compatibility with the adapter, we do not ask the server for DN attributes,
        // such as entryDN; we compute them ourselves. Some servers might not support such attributes anyway.
        result.removeAll(LdapEntry.ENTRY_DN_ATTRS);

        return result;
    }

    /**
     * Creates a {@link ConnectorObject} based on the given search result. The search result name is expected to be a
     * relative one, thus the {@code
     * baseDN} parameter is needed in order to create the whole entry DN, which is used to compute the connector
     * object's name attribute.
     */
    private ConnectorObject createConnectorObject(
            final String baseDN,
            final SearchResult result,
            final Set<String> attrsToGet,
            final boolean emptyAttrWhenNotFound) {

        final LdapEntry entry = LdapEntry.create(baseDN, result);

        final ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(oclass);
        builder.setUid(conn.getSchemaMapping().createUid(oclass, entry));
        builder.setName(conn.getSchemaMapping().createName(oclass, entry));

        final List<String> ldapGroups = new ArrayList<String>();
        final List<String> posixGroups = new ArrayList<String>();

        for (String attrName : attrsToGet) {
            Attribute attribute;
            if (LdapConstants.isLdapGroups(attrName)) {
                ldapGroups.addAll(groupHelper.getLdapGroups(entry.getDN().toString()));

                attribute = AttributeBuilder.build(LdapConstants.LDAP_GROUPS_NAME, ldapGroups);
            } else if (LdapConstants.isPosixGroups(attrName)) {
                final Set<String> posixRefAttrs = LdapUtil.getStringAttrValues(entry.getAttributes(), GroupHelper.
                        getPosixRefAttribute());

                posixGroups.addAll(groupHelper.getPosixGroups(posixRefAttrs));

                attribute = AttributeBuilder.build(LdapConstants.POSIX_GROUPS_NAME, posixGroups);
            } else if (LdapConstants.PASSWORD.is(attrName)
                    && !conn.getConfiguration().getRetrievePasswordsWithSearch()) {

                attribute = AttributeBuilder.build(attrName, new GuardedString());
            } else {
                attribute = conn.getSchemaMapping().createAttribute(oclass, attrName, entry, emptyAttrWhenNotFound);
            }

            if (attribute != null) {
                builder.addAttribute(attribute);
            }
        }

        Optional.ofNullable(StatusManagement.getInstance(conn.getConfiguration().getStatusManagementClass()).
                getStatus(result.getAttributes())).
                ifPresent(status -> builder.addAttribute(AttributeBuilder.buildEnabled(status)));

        return builder.build();
    }

    /**
     * Creates a search filter which will filter to a given {@link ObjectClass}. It will be composed of an optional
     * filter to be applied before the object class filters, the filters for all LDAP object classes for the given
     * {@code ObjectClass}, and an optional filter to be applied before the object class filters.
     */
    private String getSearchFilter(final String... optionalFilters) {
        StringBuilder builder = new StringBuilder();
        String ocFilter = getObjectClassFilter();
        int nonBlank = StringUtil.isBlank(ocFilter) ? 0 : 1;

        for (String optionalFilter : optionalFilters) {
            nonBlank += (StringUtil.isBlank(optionalFilter) ? 0 : 1);
        }

        if (nonBlank > 1) {
            builder.append("(&");
        }

        appendFilter(ocFilter, builder);

        for (String optionalFilter : optionalFilters) {
            appendFilter(optionalFilter, builder);
        }

        if (nonBlank > 1) {
            builder.append(')');
        }

        return builder.toString();
    }

    private String getObjectClassFilter() {
        StringBuilder builder = new StringBuilder();
        List<String> ldapClasses = conn.getSchemaMapping().getLdapClasses(oclass);

        boolean and = ldapClasses.size() > 1;
        if (and) {
            builder.append("(&");
        }

        for (String ldapClass : ldapClasses) {
            builder.append("(objectClass=");
            builder.append(ldapClass);
            builder.append(')');
        }

        if (and) {
            builder.append(')');
        }

        return builder.toString();
    }

    private static void appendFilter(String filter, StringBuilder toBuilder) {
        if (!StringUtil.isBlank(filter)) {
            final String trimmedUserFilter = filter.trim();
            final boolean enclose = filter.charAt(0) != '(';

            if (enclose) {
                toBuilder.append('(');
            }

            toBuilder.append(trimmedUserFilter);

            if (enclose) {
                toBuilder.append(')');
            }
        }
    }

    private List<String> getBaseDNs() {
        List<String> result;

        final QualifiedUid container = options.getContainer();

        if (container != null) {
            result = Collections.singletonList(
                    LdapSearches.findEntryDN(conn, container.getObjectClass(), container.getUid()));
        } else {
            result = Arrays.asList(baseDNs);
        }

        assert result != null;
        return result;
    }

    private LdapSearchStrategy getSearchStrategy() {
        LdapSearchStrategy result = conn.getConfiguration().newDefaultSearchStrategy(false);
        if (options.getPageSize() != null) {
            if (conn.getConfiguration().isUseVlvControls() && conn.supportsControl(VirtualListViewControl.OID)) {
                String vlvSortAttr = conn.getConfiguration().getVlvSortAttribute();
                result = new VlvIndexSearchStrategy(vlvSortAttr, options.getPageSize());
            } else if (conn.supportsControl(PagedResultsControl.OID)) {
                result = new PagedSearchStrategy(
                        options.getPageSize(),
                        options.getPagedResultsCookie(),
                        options.getPagedResultsOffset(),
                        handler instanceof SearchResultsHandler ? (SearchResultsHandler) handler : null,
                        options.getSortKeys()
                );
            }
        }

        return result;
    }

    private Set<String> getAttributesToGet(final String[] attributesToGet) {
        Set<String> result;

        if (attributesToGet != null) {
            result = CollectionUtil.newCaseInsensitiveSet();
            result.addAll(Arrays.asList(attributesToGet));
            removeNonReadableAttributes(result);
            result.add(Name.NAME);
        } else {
            // This should include Name.NAME, so no need to include it explicitly.
            result = getAttributesReturnedByDefault(conn, oclass);
        }

        // Since Uid is not in the schema, but it is required to construct a ConnectorObject.
        result.add(Uid.NAME);

        // Our password is marked as readable because of sync(). 
        // We really can't return it from search.
        if (!conn.getConfiguration().getRetrievePasswordsWithSearch()
                && result.contains(OperationalAttributes.PASSWORD_NAME)) {
            LOG.warn("Reading passwords not supported");
        }

        return result;
    }

    private void removeNonReadableAttributes(final Set<String> attributes) {
        // Since the groups attributes are fake attributes, we don't want to
        // send them to LdapSchemaMapping. This, for example, avoid an (unlikely)
        // conflict with a custom attribute defined in the server schema.
        boolean ldapGroups = attributes.remove(LdapConstants.LDAP_GROUPS_NAME);
        boolean posixGroups = attributes.remove(LdapConstants.POSIX_GROUPS_NAME);

        conn.getSchemaMapping().removeNonReadableAttributes(oclass, attributes);

        if (ldapGroups) {
            attributes.add(LdapConstants.LDAP_GROUPS_NAME);
        }

        if (posixGroups) {
            attributes.add(LdapConstants.POSIX_GROUPS_NAME);
        }
    }

    private int getLdapSearchScope() {
        String scope = options.getScope();

        if (OperationOptions.SCOPE_OBJECT.equals(scope)) {
            return SearchControls.OBJECT_SCOPE;
        } else if (OperationOptions.SCOPE_ONE_LEVEL.equals(scope)) {
            return SearchControls.ONELEVEL_SCOPE;
        } else if (OperationOptions.SCOPE_SUBTREE.equals(scope) || scope == null) {
            return SearchControls.SUBTREE_SCOPE;
        } else {
            throw new IllegalArgumentException("Invalid search scope " + scope);
        }
    }
}
