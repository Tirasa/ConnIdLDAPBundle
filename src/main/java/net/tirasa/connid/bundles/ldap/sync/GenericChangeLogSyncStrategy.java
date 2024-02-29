/*
 * ====================
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright 2011 ConnId. All rights reserved.
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
 */
package net.tirasa.connid.bundles.ldap.sync;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import net.tirasa.connid.bundles.ldap.LdapConnection;
import net.tirasa.connid.bundles.ldap.commons.LdapConstants;
import net.tirasa.connid.bundles.ldap.commons.LdapEntry;
import net.tirasa.connid.bundles.ldap.commons.LdapUtil;
import net.tirasa.connid.bundles.ldap.commons.LdifParser;
import net.tirasa.connid.bundles.ldap.commons.LdifParser.ChangeSeparator;
import net.tirasa.connid.bundles.ldap.commons.LdifParser.Line;
import net.tirasa.connid.bundles.ldap.commons.LdifParser.NameValue;
import net.tirasa.connid.bundles.ldap.commons.LdifParser.Separator;
import net.tirasa.connid.bundles.ldap.commons.PasswordDecryptor;
import net.tirasa.connid.bundles.ldap.search.LdapFilter;
import net.tirasa.connid.bundles.ldap.search.LdapSearch;
import net.tirasa.connid.bundles.ldap.search.LdapSearchStrategy;
import net.tirasa.connid.bundles.ldap.search.LdapSearches;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.AttributesAccessor;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.common.objects.SyncDelta;
import org.identityconnectors.framework.common.objects.SyncDeltaBuilder;
import org.identityconnectors.framework.common.objects.SyncDeltaType;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.spi.SearchResultsHandler;

/**
 * An implementation of the sync operation based on the retro change log
 * plugin of Sun Directory Server.
 */
public class GenericChangeLogSyncStrategy implements LdapSyncStrategy {

    // TODO detect that the change log has been trimmed.
    protected static final Log LOG = Log.getLog(LdapSyncStrategy.class);

    /**
     * The list of attribute operations supported by the "modify" LDIF change type.
     */
    protected static final Set<String> LDIF_MODIFY_OPS;

    protected static final Set<String> LDAP_DN_ATTRIBUTES;

    protected final LdapConnection conn;

    protected Set<String> oclassesToSync;

    protected Set<String> attrsToSync;

    protected PasswordDecryptor passwordDecryptor;

    static {
        LDIF_MODIFY_OPS = CollectionUtil.newCaseInsensitiveSet();
        LDIF_MODIFY_OPS.add("add");
        LDIF_MODIFY_OPS.add("delete");
        LDIF_MODIFY_OPS.add("replace");

        LDAP_DN_ATTRIBUTES = CollectionUtil.newCaseInsensitiveSet();
        LDAP_DN_ATTRIBUTES.add("uid");
        LDAP_DN_ATTRIBUTES.add("cn");
    }

    public GenericChangeLogSyncStrategy(LdapConnection conn) {
        this.conn = conn;
    }

    protected SyncToken getLatestSyncTokenPaged(ObjectClass oclass, OperationOptionsBuilder builder) {
        LOG.ok("Getting latest sync token with pages of size {0}", conn.getConfiguration().getChangeLogBlockSize());

        final String[] cookies = new String[] { null };
        final int[] maxChangeNumber = { 0 };

        do {
            if (cookies[0] != null) {
                LOG.ok("Setting paged results cookie to {0}", cookies[0]);
                builder.setPagedResultsCookie(cookies[0]);
            }

            cookies[0] = null;

            SearchResultsHandler handler = new SearchResultsHandler() {

                @Override
                public boolean handle(final ConnectorObject object) {
                    Attribute changeNumberAttr = object.getAttributeByName(getChangeNumberAttribute());
                    if (changeNumberAttr != null) {
                        int changeNumber = convertToInt(AttributeUtil.getStringValue(changeNumberAttr), -1);
                        if (changeNumber > maxChangeNumber[0]) {
                            maxChangeNumber[0] = changeNumber;
                        }
                    }

                    return true;
                }

                @Override
                public void handleResult(final SearchResult result) {
                    if (result.isAllResultsReturned()) {
                        cookies[0] = result.getPagedResultsCookie();
                    }
                }
            };

            LdapSearch search = new LdapSearch(this.conn,
                    oclass,
                    null,
                    handler,
                    builder.build(),
                    conn.getConfiguration().getChangeLogContext());

            search.execute();
        } while (cookies[0] != null);

        return new SyncToken(maxChangeNumber[0]);
    }

    protected SyncToken getLatestSyncTokenDefault(ObjectClass oclass, OperationOptionsBuilder builder) {
        final int[] maxChangeNumber = { 0 };
        LOG.ok("Getting latest sync token with a regular search");

        ResultsHandler handler = new ResultsHandler() {

            @Override
            public boolean handle(final ConnectorObject object) {
                int changeNumber = convertToInt((String) object.getAttributeByName(getChangeNumberAttribute()).
                        getValue().get(0), -1);
                if (changeNumber > maxChangeNumber[0]) {
                    maxChangeNumber[0] = changeNumber;
                }

                return true;
            }
        };

        LdapSearch search = new LdapSearch(this.conn,
                oclass,
                null,
                handler,
                builder.build(),
                conn.getConfiguration().getChangeLogContext());

        search.execute();

        return new SyncToken(maxChangeNumber[0]);
    }

    @Override
    public SyncToken getLatestSyncToken(ObjectClass oclass) {
        String changeNumberAttr = getChangeNumberAttribute();

        OperationOptionsBuilder builder = new OperationOptionsBuilder();
        builder.setAttributesToGet(changeNumberAttr);
        builder.setScope(OperationOptions.SCOPE_ONE_LEVEL);
        builder.setPageSize(conn.getConfiguration().getChangeLogBlockSize());
        builder.setOption(LdapSearch.OP_IGNORE_BUILT_IN_FILTERS, true);
        builder.setOption(LdapConstants.SEARCH_FILTER_NAME, "(objectClass=changelogEntry)");

        Class<? extends LdapSearchStrategy> searchStrategyClass = LdapSearchStrategy.getSearchStrategy(conn, builder.
                build());

        switch (searchStrategyClass.getSimpleName()) {
            case "PagedSearchStrategy":
                if (conn.getConfiguration().getChangeLogPagingSupport()) {
                    return getLatestSyncTokenPaged(oclass, builder);
                } else {
                    return getLatestSyncTokenDefault(oclass, builder);
                }
            default:
                return getLatestSyncTokenDefault(oclass, builder);
        }
    }

    @Override
    public void sync(
            final SyncToken token,
            final SyncResultsHandler handler,
            final OperationOptions options,
            final ObjectClass oclass) {
        final String changeNumberAttr = getChangeNumberAttribute();

        OperationOptionsBuilder builder = new OperationOptionsBuilder();
        builder.setScope(OperationOptions.SCOPE_ONE_LEVEL);
        builder.setAttributesToGet(
                changeNumberAttr,
                "targetDN",
                "changeType",
                "changes",
                "newRdn",
                "deleteOldRdn",
                "newSuperior"
        );
        builder.setOption(LdapSearch.OP_IGNORE_BUILT_IN_FILTERS, true);

        final int[] currentChangeNumber = { getStartChangeNumber(token) };

        final boolean[] results = new boolean[1];

        ResultsHandler resultsHandler = new ResultsHandler() {

            @Override
            public boolean handle(final ConnectorObject object) {
                results[0] = true;

                Attribute changeNumberAttr = object.getAttributeByName(getChangeNumberAttribute());
                int changeNumber = -1;
                if (changeNumberAttr != null) {
                    changeNumber = convertToInt(AttributeUtil.getStringValue(changeNumberAttr), -1);
                    if (changeNumber > currentChangeNumber[0]) {
                        currentChangeNumber[0] = changeNumber;
                    }
                }

                SyncDelta delta;
                try {
                    delta = createSyncDelta(object, changeNumber, options.getAttributesToGet(), oclass);
                } catch (InvalidNameException e) {
                    delta = null;
                }

                if (delta != null) {
                    return handler.handle(delta);
                }
                return true;
            }
        };

        do {
            results[0] = false;

            builder.setOption(
                    LdapConstants.SEARCH_FILTER_NAME,
                    getChangeLogSearchFilter(changeNumberAttr, currentChangeNumber[0]));

            LdapSearch search = new LdapSearch(conn,
                    oclass,
                    null,
                    resultsHandler,
                    builder.build(),
                    conn.getConfiguration().getChangeLogContext());

            search.execute();

            // We have already processed the current change.
            // In the next cycle we want to start with the next change.
            if (results[0]) {
                currentChangeNumber[0]++;
            }

        } while (results[0]);
    }

    protected SyncDelta createSyncDelta(
            final ConnectorObject inputObject,
            final int changeNumber,
            final String[] attrsToGetOption,
            ObjectClass oclass) throws InvalidNameException {

        LOG.ok("Attempting to create sync delta for log entry {0}", changeNumber);

        final AttributesAccessor inputAttrs = new AttributesAccessor(inputObject.getAttributes());

        final String targetDN = inputAttrs.findString("targetDN");

        if (targetDN == null) {
            LOG.error("Skipping log entry because it does not have a targetDN attribute");
            return null;
        }

        final LdapName targetName = LdapUtil.quietCreateLdapName(targetDN);

        if (filterOutByBaseContexts(targetName)) {
            LOG.ok("Skipping log entry because it does not match any of the "
                    + "base contexts to synchronize");
            return null;
        }

        final String changeType = inputAttrs.findString("changeType");

        SyncDeltaType deltaType = getSyncDeltaType(changeType);

        SyncDeltaBuilder syncDeltaBuilder = new SyncDeltaBuilder();
        syncDeltaBuilder.setToken(new SyncToken(changeNumber));
        syncDeltaBuilder.setDeltaType(deltaType);

        if (deltaType.equals(SyncDeltaType.DELETE)) {
            return createDeletionSyncDelta(syncDeltaBuilder, targetDN, oclass, inputAttrs);
        }

        final String changes = inputAttrs.findString("changes");

        final Map<String, List<Object>> attrChanges = getAttributeChanges(changeType, changes);

        if (filterOutByModifiersNames(attrChanges)) {
            LOG.ok("Skipping entry because modifiersName is in the list of modifiersName's to filter out");
            return null;
        }

        if (filterOutByAttributes(attrChanges)) {
            LOG.ok("Skipping entry because no changed attributes in the list of attributes to synchronize");
            return null;
        }

        // If the change type was modrdn, we need to compute the DN that the entry
        // was modified to.
        String newTargetDN = targetDN;

        if ("modrdn".equalsIgnoreCase(changeType)) {
            final String newRdn = inputAttrs.findString("newRdn");

            if (StringUtil.isBlank(newRdn)) {
                LOG.error("Skipping log entry because it does not have a newRdn attribute");
                return null;
            }

            final String newSuperior = inputAttrs.findString("newSuperior");

            newTargetDN = getNewTargetDN(targetName, newSuperior, newRdn);
        }

        // Always specify the attributes to get. This will return attributes with
        // empty values when the attribute is not present, allowing the client to
        // detect that the attribute has been removed.
        Set<String> attrsToGet;

        if (attrsToGetOption != null) {
            attrsToGet = CollectionUtil.newSet(attrsToGetOption);
            // Do not retrieve the password attribute from the entry (usually it is an unusable
            // hashed value anyway). We will use the one from the change log below.
            attrsToGet.remove(OperationalAttributes.PASSWORD_NAME);
        } else {
            attrsToGet = CollectionUtil.newSet(LdapSearch.getAttributesReturnedByDefault(conn, oclass));
        }
        // If objectClass is not in the list of attributes to get, prepare to remove it later.
        boolean removeObjectClass = attrsToGet.add("objectClass");

        LdapFilter filter = LdapFilter.forEntryDN(newTargetDN).withNativeFilter(getModifiedEntrySearchFilter(oclass));

        ConnectorObject object = LdapSearches.findObject(conn, oclass, filter, attrsToGet.toArray(new String[0]));

        if (object == null) {
            LOG.ok("Skipping entry because the modified entry is missing, "
                    + "not of the right object class, or not matching the search filter");
            return null;
        }

        Attribute oclassAttr = object.getAttributeByName("objectClass");

        final List<String> objectClasses = LdapUtil.checkedListByFilter(
                CollectionUtil.nullAsEmpty(oclassAttr.getValue()), String.class);

        if (filterOutByObjectClasses(objectClasses)) {
            LOG.ok("Skipping entry because no object class in the list of "
                    + "object classes to synchronize");
            return null;
        }

        Attribute passwordAttr = null;

        if (conn.getConfiguration().isSynchronizePasswords()) {
            final List<Object> passwordValues = attrChanges.get(
                    conn.getConfiguration().getPasswordAttributeToSynchronize());

            if (!passwordValues.isEmpty()) {
                byte[] encryptedPwd = (byte[]) passwordValues.get(0);

                final String decryptedPwd = getPasswordDecryptor().decryptPassword(encryptedPwd);

                passwordAttr = AttributeBuilder.buildPassword(new GuardedString(decryptedPwd.toCharArray()));
            }
        }

        if (removeObjectClass || passwordAttr != null) {
            ConnectorObjectBuilder objectBuilder = new ConnectorObjectBuilder();
            objectBuilder.setObjectClass(object.getObjectClass());
            objectBuilder.setUid(object.getUid());
            objectBuilder.setName(object.getName());

            if (removeObjectClass) {
                for (Attribute attr : object.getAttributes()) {
                    if (attr != oclassAttr) {
                        objectBuilder.addAttribute(attr);
                    }
                }
            } else {
                objectBuilder.addAttributes(object.getAttributes());
            }

            if (passwordAttr != null) {
                objectBuilder.addAttribute(passwordAttr);
            }

            object = objectBuilder.build();
        }

        LOG.ok("Creating sync delta for created or updated entry");

        if ("modrdn".equalsIgnoreCase(changeType)) {
            String uidAttr = conn.getSchema().getLdapUidAttribute(oclass);

            // We can only set the previous Uid if it is the entry DN, 
            // which is readily available.
            if (LdapEntry.isDNAttribute(uidAttr)) {
                syncDeltaBuilder.setPreviousUid(conn.getSchema().createUid(oclass, targetDN));
            }
        }

        syncDeltaBuilder.setUid(object.getUid());
        syncDeltaBuilder.setObject(object);

        return syncDeltaBuilder.build();
    }

    protected SyncDelta createDeletionSyncDelta(
            final SyncDeltaBuilder syncDeltaBuilder,
            final String targetDN,
            final ObjectClass oclass,
            final AttributesAccessor inputAttrs)
            throws InvalidNameException {

        LOG.ok("Creating sync delta for deleted entry {0}", targetDN);

        Uid deletedUid = new Uid(targetDN);

        // Build an empty connector object, with minimal information - LDAP-8
        ConnectorObjectBuilder objectBuilder = new ConnectorObjectBuilder();
        objectBuilder.setObjectClass(oclass);
        objectBuilder.setUid(deletedUid);
        objectBuilder.setName("fake-dn");
        objectBuilder.addAttributes(Collections.<Attribute>emptySet());

        syncDeltaBuilder.setUid(deletedUid);
        syncDeltaBuilder.setObject(objectBuilder.build());

        return syncDeltaBuilder.build();
    }

    protected String getNewTargetDN(
            final LdapName targetName,
            final String newSuperior,
            final String newRdn) {

        try {
            LdapName newTargetName;
            if (newSuperior == null) {
                newTargetName = new LdapName(targetName.getRdns());
                if (newTargetName.size() > 0) {
                    newTargetName.remove(targetName.size() - 1);
                }
            } else {
                newTargetName = LdapUtil.quietCreateLdapName(newSuperior);
            }
            newTargetName.add(newRdn);
            return newTargetName.toString();
        } catch (InvalidNameException e) {
            throw new ConnectorException(e);
        }
    }

    protected boolean filterOutByBaseContexts(final LdapName targetName) {
        List<LdapName> baseContexts = conn.getConfiguration().
                getBaseContextsToSynchronizeAsLdapNames();
        if (baseContexts.isEmpty()) {
            baseContexts = conn.getConfiguration().getBaseContextsAsLdapNames();
        }
        return !LdapUtil.isUnderContexts(targetName, baseContexts);
    }

    protected boolean filterOutByModifiersNames(final Map<String, List<Object>> changes) {
        Set<LdapName> filter = conn.getConfiguration().
                getModifiersNamesToFilterOutAsLdapNames();
        if (filter.isEmpty()) {
            LOG.ok("Filtering by modifiersName disabled");
            return false;
        }
        List<?> modifiersNameValues = changes.get("modifiersName");
        if (CollectionUtil.isEmpty(modifiersNameValues)) {
            LOG.ok("Not filtering by modifiersName because not set for this entry");
            return false;
        }
        LdapName modifiersName = LdapUtil.quietCreateLdapName(modifiersNameValues.get(0).toString());
        return filter.contains(modifiersName);
    }

    protected boolean filterOutByAttributes(final Map<String, List<Object>> attrChanges) {
        Set<String> filter = getAttributesToSynchronize();
        if (filter.isEmpty()) {
            LOG.ok("Filtering by attributes disabled");
            return false;
        }
        Set<String> changedAttrs = attrChanges.keySet();
        return !containsAny(filter, changedAttrs);
    }

    protected boolean filterOutByObjectClasses(final List<String> objectClasses) {
        Set<String> filter = getObjectClassesToSynchronize();
        if (filter.isEmpty()) {
            LOG.ok("Filtering by object class disabled");
            return false;
        }
        return !containsAny(filter, objectClasses);
    }

    protected SyncDeltaType getSyncDeltaType(final String changeType) {
        if ("delete".equalsIgnoreCase(changeType)) {
            return SyncDeltaType.DELETE;
        }
        return SyncDeltaType.CREATE_OR_UPDATE;
    }

    protected String getModifiedEntrySearchFilter(ObjectClass oclass) {
        if (oclass.equals(ObjectClass.ACCOUNT)) {
            return conn.getConfiguration().getAccountSynchronizationFilter();
        }
        return null;
    }

    protected int getStartChangeNumber(final SyncToken lastToken) {
        return lastToken != null ? (Integer) lastToken.getValue() + 1 : 0;
    }

    protected Map<String, List<Object>> getAttributeChanges(final String changeType, final String ldif) {
        final Map<String, List<Object>> result = CollectionUtil.newCaseInsensitiveMap();

        if ("modify".equalsIgnoreCase(changeType)) {
            LdifParser parser = new LdifParser(ldif);
            Iterator<Line> lines = parser.iterator();
            while (lines.hasNext()) {
                Line line = lines.next();
                // We only expect one change, so ignore any change separators.
                if (line instanceof Separator || line instanceof ChangeSeparator) {
                    continue;
                }
                NameValue nameValue = (NameValue) line;
                String operation = nameValue.getName();
                String attrName = nameValue.getValue();
                if (LDIF_MODIFY_OPS.contains(operation)) {
                    List<Object> values = new ArrayList<>();
                    while (lines.hasNext()) {
                        line = lines.next();
                        if (line instanceof Separator) {
                            break;
                        }
                        nameValue = (NameValue) line;
                        Object value = decodeAttributeValue(nameValue);
                        if (value != null) {
                            values.add(value);
                        }
                    }
                    if (!values.isEmpty()) {
                        result.put(attrName, values);
                    }
                }
            }
        } else if ("add".equalsIgnoreCase(changeType)) {
            LdifParser parser = new LdifParser(ldif);
            for (Line line : parser) {
                // We only expect one change, so ignore any change separators.
                if (line instanceof Separator || line instanceof ChangeSeparator) {
                    continue;
                }
                NameValue nameValue = (NameValue) line;
                Object value = decodeAttributeValue(nameValue);
                if (value != null) {
                    List<Object> values = result.get(nameValue.getName());
                    if (values == null) {
                        values = new ArrayList<>();
                        result.put(nameValue.getName(), values);
                    }
                    values.add(value);
                }
            }
        }

        // Returning an empty map when changeType is "delete" or "modrdn".
        return result;
    }

    protected Object decodeAttributeValue(final NameValue nameValue) {
        String value = nameValue.getValue();
        if (value.startsWith(":")) {
            // This is a Base64 encoded value...
            String base64 = value.substring(1).trim();
            try {
                return Base64.getDecoder().decode(base64);
                // TODO the adapter had code here to convert the byte array
                // to a string if the attribute was of a string type. Since
                // that information is in the schema and we don't have access
                // to the resource schema, leaving that functionality out for now.
            } catch (Exception e) {
                LOG.error("Could not decode attribute {0} with Base64 value {1}",
                        nameValue.getName(), nameValue.getValue());
                return null;
            }
        } else {
            return value;
        }
    }

    protected String getChangeLogSearchFilter(final String changeNumberAttr, final int startChangeNumber) {
        int blockSize = conn.getConfiguration().getChangeLogBlockSize();
        boolean filterWithOrInsteadOfAnd = conn.getConfiguration().
                isFilterWithOrInsteadOfAnd();
        boolean filterByLogEntryOClass = !conn.getConfiguration().
                isRemoveLogEntryObjectClassFromFilter();

        StringBuilder result = new StringBuilder();
        if (filterWithOrInsteadOfAnd) {
            if (filterByLogEntryOClass) {
                result.append("(&(objectClass=changeLogEntry)");
            }
            result.append("(|(");
            result.append(changeNumberAttr);
            result.append('=');
            result.append(startChangeNumber);
            result.append(')');

            int endChangeNumber = startChangeNumber + blockSize;
            for (int i = startChangeNumber + 1; i <= endChangeNumber; i++) {
                result.append("(");
                result.append(changeNumberAttr);
                result.append('=');
                result.append(i);
                result.append(')');
            }

            result.append(')');
            if (filterByLogEntryOClass) {
                result.append(')');
            }
        } else {
            result.append("(&");
            if (filterByLogEntryOClass) {
                result.append("(objectClass=changeLogEntry)");
            }
            result.append("(");
            result.append(changeNumberAttr);
            result.append(">=");
            result.append(startChangeNumber);
            result.append(')');

            int endChangeNumber = startChangeNumber + blockSize;
            result.append("(");
            result.append(changeNumberAttr);
            result.append("<=");
            result.append(endChangeNumber);
            result.append(')');

            result.append(')');
        }

        return result.toString();
    }

    protected String getChangeNumberAttribute() {
        String result = conn.getConfiguration().getChangeNumberAttribute();
        if (StringUtil.isBlank(result)) {
            result = "changeNumber";
        }
        return result;
    }

    protected Set<String> getAttributesToSynchronize() {
        if (attrsToSync == null) {
            Set<String> result = CollectionUtil.newCaseInsensitiveSet();
            result.addAll(Arrays.asList(LdapUtil.nullAsEmpty(conn.getConfiguration().getAttributesToSynchronize())));
            if (conn.getConfiguration().isSynchronizePasswords()) {
                result.add(conn.getConfiguration().
                        getPasswordAttributeToSynchronize());
            }
            attrsToSync = result;
        }
        return attrsToSync;
    }

    protected Set<String> getObjectClassesToSynchronize() {
        if (oclassesToSync == null) {
            Set<String> result = CollectionUtil.newCaseInsensitiveSet();
            result.addAll(Arrays.asList(LdapUtil.nullAsEmpty(conn.getConfiguration().getObjectClassesToSynchronize())));
            oclassesToSync = result;
        }
        return oclassesToSync;
    }

    protected PasswordDecryptor getPasswordDecryptor() {
        if (passwordDecryptor == null) {
            conn.getConfiguration().getPasswordDecryptionKey().access(decryptionKey -> {
                conn.getConfiguration().getPasswordDecryptionInitializationVector().access(decryptionIV -> {
                    passwordDecryptor = new PasswordDecryptor(decryptionKey, decryptionIV);
                });
            });
        }
        assert passwordDecryptor != null;
        return passwordDecryptor;
    }

    protected boolean containsAny(
            final Set<String> haystack, final Collection<String> needles) {
        for (String needle : needles) {
            if (haystack.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    protected Uid createUid(final String uidAttr, final String targetDN) throws InvalidNameException {
        Rdn matchingRnd = null;
        for (Rdn rdn : new LdapName(targetDN).getRdns()) {
            if (uidAttr.equalsIgnoreCase(rdn.getType())) {
                matchingRnd = rdn;
            }
        }
        return matchingRnd == null ? null : new Uid(matchingRnd.getValue().toString());
    }

    protected static int convertToInt(String number, final int def) {
        int result = def;
        if (number != null && number.length() > 0) {
            int decimal = number.indexOf('.');
            if (decimal > 0) {
                number = number.substring(0, decimal);
            }
            try {
                result = Integer.parseInt(number);
            } catch (NumberFormatException e) {
                // Ignore.
            }
        }
        return result;
    }
}
