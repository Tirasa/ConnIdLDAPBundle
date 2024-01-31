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
package net.tirasa.connid.bundles.ldap;

import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import net.tirasa.connid.bundles.ldap.commons.LdapConstants;
import net.tirasa.connid.bundles.ldap.commons.LdapUtil;
import net.tirasa.connid.bundles.ldap.commons.ObjectClassMappingConfig;
import net.tirasa.connid.bundles.ldap.schema.LdapSchema;
import net.tirasa.connid.bundles.ldap.search.DefaultSearchStrategy;
import net.tirasa.connid.bundles.ldap.sync.LdapSyncStrategy;
import net.tirasa.connid.bundles.ldap.sync.sunds.SunDSChangeLogSyncStrategy;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.EqualsHashCodeBuilder;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.security.GuardedByteArray;
import org.identityconnectors.common.security.GuardedByteArray.Accessor;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;
import org.identityconnectors.framework.spi.operations.SyncOp;

/**
 * Encapsulates the LDAP connector's configuration.
 *
 * @author Andrei Badea
 */
public class LdapConfiguration extends AbstractConfiguration {

    public enum SearchScope {
        object,
        onelevel,
        subtree;

    }

    // XXX should try to connect to the resource.
    public static final int DEFAULT_PORT = 389;

    private static final String DEFAULT_ID_ATTRIBUTE = "entryUUID";

    // Exposed configuration properties.
    /**
     * The LDAP host server to connect to.
     */
    private String host;

    /**
     * The port the server is listening on.
     */
    private int port = DEFAULT_PORT;

    /**
     * Whether the port is a secure SSL port.
     */
    private boolean ssl;

    /**
     * LDAP URL's to connect to if the main server specified through the host and port properties is not available.
     */
    private String[] failover = {};

    /**
     * The bind DN for performing operations on the server.
     */
    private String principal;

    /**
     * The bind password associated with the bind DN.
     */
    private GuardedString credentials;

    /**
     * The base DNs for operations on the server.
     */
    private String[] baseContexts = {};

    /**
     * The name of the attribute which the predefined PASSWORD attribute will be written to.
     */
    private String passwordAttribute = "userPassword";

    /**
     * A search filter that any account needs to match in order to be returned.
     */
    private String accountSearchFilter = null;

    /**
     * A search filter that any group needs to match in order to be returned
     */
    private String groupSearchFilter = null;

    /**
     * A search filter that any anyObject needs to match in order to be returned
     */
    private String anyObjectSearchFilter = null;

    /**
     * The LDAP attribute holding the member for non-POSIX static groups.
     */
    private String groupMemberAttribute = "uniqueMember";

    /**
     * If true, will modify group membership of renamed/deleted entries.
     */
    private boolean maintainLdapGroupMembership = false;

    /**
     * If true, will modify POSIX group membership of renamed/deleted entries.
     */
    private boolean maintainPosixGroupMembership = false;

    /**
     * If true, will automatically add the configured principal as first member of a new group.
     */
    private boolean addPrincipalToNewGroups = false;

    /**
     * If the server stores passwords in clear text, we will hash them with the algorithm specified here.
     */
    private String passwordHashAlgorithm;

    /**
     * If true, when binding check for the Password Expired control (and also Password Policy control) and throw
     * exceptions (PasswordExpiredException, etc.) appropriately.
     */
    private boolean respectResourcePasswordPolicyChangeAfterReset;

    /**
     * If true, VLV index search will be used instead of LDAP controls.
     */
    private boolean useVlvControls = false;

    /**
     * The attribute used as the sort key for the VLV index.
     */
    private String vlvSortAttribute = "uid";

    /**
     * The LDAP attribute to map Uid to.
     */
    private String uidAttribute = "entryUUID";

    /**
     * The LDAP attribute to map Gid to.
     */
    private String gidAttribute = "entryUUID";

    /**
     * The LDAP attribute to map Aoid to
     */
    private String aoidAttribute = "entryUUID";

    /**
     * Whether to read the schema from the server.
     */
    private boolean readSchema = true;

    // Sync configuration properties.
    private String[] baseContextsToSynchronize = {};

    private String[] objectClassesToSynchronize = { "inetOrgPerson" };

    private String[] attributesToSynchronize = {};

    private String[] modifiersNamesToFilterOut = {};

    private String accountSynchronizationFilter;

    private int changeLogBlockSize = 100;

    private String changeNumberAttribute = "changeNumber";

    private String changeLogContext = "cn=changelog";

    private boolean filterWithOrInsteadOfAnd;

    private boolean removeLogEntryObjectClassFromFilter = true;

    private boolean synchronizePasswords;

    private String passwordAttributeToSynchronize;

    private GuardedByteArray passwordDecryptionKey;

    private GuardedByteArray passwordDecryptionInitializationVector;

    private String statusManagementClass;

    private String dnAttribute = "entryDN";

    private String syncStrategy = SunDSChangeLogSyncStrategy.class.getName();

    private Class<? extends LdapSyncStrategy> syncStrategyClass = null;

    private Class<? extends LdapSyncStrategy> fallbackSyncStrategyClass = SunDSChangeLogSyncStrategy.class;

    private Class<? extends LdapConnection> connectionClass = LdapConnection.class;

    /**
     * The SearchScope for user objects
     */
    private SearchScope userSearchScope = SearchScope.subtree;

    /**
     * The SearchScope for group objects
     */
    private SearchScope groupSearchScope = SearchScope.subtree;

    /**
     * The SearchScope for anyObject objects
     */
    private SearchScope anyObjectSearchScope = SearchScope.subtree;

    /**
     * Whether to retrieve passwords when searching. The default is "false".
     */
    private boolean retrievePasswordsWithSearch;

    // Other state.
    private final ObjectClassMappingConfig accountConfig = new ObjectClassMappingConfig(
            ObjectClass.ACCOUNT,
            CollectionUtil.newList("top", "person", "organizationalPerson", "inetOrgPerson"),
            false, CollectionUtil.newList("uid", "cn"),
            LdapConstants.PASSWORD);

    private final ObjectClassMappingConfig groupConfig = new ObjectClassMappingConfig(
            ObjectClass.GROUP,
            CollectionUtil.newList("top", "groupOfUniqueNames"),
            false, CollectionUtil.newList("cn"));

    private final ObjectClassMappingConfig anyObjectConfig = new ObjectClassMappingConfig(
            LdapSchema.ANY_OBJECT_CLASS,
            CollectionUtil.newList("top"),
            false, CollectionUtil.newList(DEFAULT_ID_ATTRIBUTE));

    private final ObjectClassMappingConfig allConfig = new ObjectClassMappingConfig(
            ObjectClass.ALL,
            CollectionUtil.newList("top"),
            false, CollectionUtil.newList(DEFAULT_ID_ATTRIBUTE));

    // Other state not to be included in hashCode/equals.
    private List<LdapName> baseContextsAsLdapNames;

    private List<LdapName> baseContextsToSynchronizeAsLdapNames;

    private Set<LdapName> modifiersNamesToFilterOutAsLdapNames;

    /**
     * Used to specify the read timeout for an LDAP operation in milliseconds
     */
    private long readTimeout = 0;

    /**
     * Used to specify the connect timeout for connecting to the ldap server in milliseconds
     */
    private long connectTimeout = 0;

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate() {
        checkNotBlank(host, "host.notBlank");

        if (port < 0 || port > 0xffff) {
            failValidation("port.legalValue");
        }

        checkNotEmpty(baseContexts, "baseContexts.notEmpty");
        checkNoBlankValues(baseContexts, "baseContexts.noBlankValues");
        checkNoInvalidLdapNames(baseContexts, "baseContexts.noInvalidLdapNames");

        checkNotBlank(passwordAttribute, "passwordAttribute.notBlank");

        checkNotEmpty(accountConfig.getLdapClasses(), "accountObjectClasses.notEmpty");
        checkNoBlankValues(accountConfig.getLdapClasses(), "accountObjectClasses.noBlankValues");

        checkNotEmpty(accountConfig.getShortNameLdapAttributes(), "accountUserNameAttributes.notEmpty");
        checkNoBlankValues(accountConfig.getShortNameLdapAttributes(), "accountUserNameAttributes.noBlankValues");

        checkNotEmpty(groupConfig.getLdapClasses(), "groupObjectClasses.notEmpty");
        checkNoBlankValues(groupConfig.getLdapClasses(), "groupObjectClasses.noBlankValues");

        checkNotEmpty(groupConfig.getShortNameLdapAttributes(), "groupNameAttributes.notEmpty");
        checkNoBlankValues(groupConfig.getShortNameLdapAttributes(), "groupNameAttributes.noBlankValues");

        checkNotEmpty(anyObjectConfig.getLdapClasses(), "anyObjectClasses.notEmpty");
        checkNoBlankValues(anyObjectConfig.getLdapClasses(), "anyObjectClasses.noBlankValues");

        checkNotEmpty(anyObjectConfig.getShortNameLdapAttributes(), "anyObjectNameAttributes.notEmpty");
        checkNoBlankValues(anyObjectConfig.getShortNameLdapAttributes(), "anyObjectNameAttributes.noBlankValues");

        checkNotBlank(getUserSearchScope(), "userSearchScope.notBlank");
        checkValidScope(getUserSearchScope(), "userSearchScope.invalidScope");

        checkNotBlank(getGroupSearchScope(), "groupSearchScope.notBlank");
        checkValidScope(getGroupSearchScope(), "groupSearchScope.invalidScope");

        checkNotBlank(getAnyObjectSearchScope(), "anyObjectSearchScope.notBlank");
        checkValidScope(getAnyObjectSearchScope(), "anyObjectSearchScope.invalidScope");

        checkNotBlank(groupMemberAttribute, "groupMemberAttribute.notBlank");

        checkNotBlank(vlvSortAttribute, "vlvSortAttribute.notBlank");

        if (baseContextsToSynchronize != null) {
            checkNoBlankValues(baseContextsToSynchronize, "baseContextsToSynchronize.noBlankValues");
            checkNoInvalidLdapNames(baseContextsToSynchronize, "baseContextsToSynchronize.noInvalidLdapNames");
        }

        checkNotEmpty(objectClassesToSynchronize, "objectClassesToSynchronize.notEmpty");
        checkNoBlankValues(objectClassesToSynchronize, "objectClassesToSynchronize.noBlankValues");

        if (attributesToSynchronize != null) {
            checkNoBlankValues(attributesToSynchronize, "attributesToSynchronize.noBlankValues");
        }

        if (modifiersNamesToFilterOut != null) {
            checkNoBlankValues(modifiersNamesToFilterOut, "modifiersNamesToFilterOut.noBlankValues");
            checkNoInvalidLdapNames(modifiersNamesToFilterOut, "modifiersNamesToFilterOut.noInvalidLdapNames");
        }

        checkNotBlank(changeNumberAttribute, "changeNumberAttribute.notBlank");

        if (changeLogBlockSize <= 0) {
            failValidation("changeLogBlockSize.legalValue");
        }

        checkNotBlank(changeLogContext, "changeLogContext.notBlank");

        if (synchronizePasswords) {
            checkNotBlank(passwordAttributeToSynchronize, "passwordAttributeToSynchronize.notBlank");
            checkNotBlank(passwordDecryptionKey, "decryptionKey.notBlank");
            checkNotBlank(passwordDecryptionInitializationVector, "decryptionInitializationVector.notBlank");
        }

        checkNotBlank(syncStrategy, "syncStrategy.notBlank");
        checkLdapSyncStrategy();
    }

    protected void checkNotBlank(String value, String errorMessage) {
        if (StringUtil.isBlank(value)) {
            failValidation(errorMessage);
        }
    }

    protected void checkNotBlank(GuardedByteArray array, String errorMessage) {
        final int[] length = { 0 };
        if (array != null) {
            array.access(new Accessor() {

                @Override
                public void access(byte[] clearBytes) {
                    length[0] = clearBytes.length;
                }
            });
        }
        if (length[0] == 0) {
            failValidation(errorMessage);
        }
    }

    @SuppressWarnings("unchecked")
    protected void checkLdapSyncStrategy() {
        try {
            Class<?> clazz = Class.forName(syncStrategy);
            if (LdapSyncStrategy.class.isAssignableFrom(clazz) && !Modifier.isAbstract(clazz.getModifiers())) {
                syncStrategyClass = (Class<? extends LdapSyncStrategy>) clazz;
            } else {
                failValidation("syncStrategy.classNotSyncStrategy");
            }
        } catch (ClassNotFoundException e) {
            failValidation("syncStrategy.classNotFound");
        }
    }

    protected void checkNotEmpty(Collection<?> collection, String errorMessage) {
        if (collection.isEmpty()) {
            failValidation(errorMessage);
        }
    }

    protected void checkNotEmpty(String[] array, String errorMessage) {
        if (array == null || array.length < 1) {
            failValidation(errorMessage);
        }
    }

    protected void checkNoBlankValues(Collection<String> collection, String errorMessage) {
        for (String each : collection) {
            if (StringUtil.isBlank(each)) {
                failValidation(errorMessage);
            }
        }
    }

    protected void checkNoBlankValues(String[] array, String errorMessage) {
        for (String each : array) {
            if (StringUtil.isBlank(each)) {
                failValidation(errorMessage);
            }
        }
    }

    protected void checkNoInvalidLdapNames(String[] array, String errorMessage) {
        for (String each : array) {
            try {
                new LdapName(each);
            } catch (InvalidNameException e) {
                failValidation(errorMessage, each);
            }
        }
    }

    protected void checkValidScope(String scope, String errorMessage) {
        switch (scope) {
            case OperationOptions.SCOPE_OBJECT:
            case OperationOptions.SCOPE_ONE_LEVEL:
            case OperationOptions.SCOPE_SUBTREE:
                break;
            default:
                failValidation(errorMessage);
        }
    }

    protected void failValidation(String key, Object... args) {
        String message = getConnectorMessages().format(key, null, args);
        throw new ConfigurationException(message);
    }

    public DefaultSearchStrategy newDefaultSearchStrategy(final boolean ignoreNonExistingBaseDN) {
        return new DefaultSearchStrategy(ignoreNonExistingBaseDN);
    }

    @ConfigurationProperty(order = 1, required = true,
            displayMessageKey = "host.display",
            helpMessageKey = "host.help")
    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    @ConfigurationProperty(order = 2,
            displayMessageKey = "port.display",
            helpMessageKey = "port.help")
    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    @ConfigurationProperty(order = 3,
            displayMessageKey = "ssl.display",
            helpMessageKey = "ssl.help")
    public boolean isSsl() {
        return ssl;
    }

    public void setSsl(boolean ssl) {
        this.ssl = ssl;
    }

    @ConfigurationProperty(order = 4,
            displayMessageKey = "failover.display",
            helpMessageKey = "failover.help")
    public String[] getFailover() {
        return failover.clone();
    }

    public void setFailover(String... failover) {
        this.failover = failover;
    }

    @ConfigurationProperty(order = 5,
            displayMessageKey = "principal.display",
            helpMessageKey = "principal.help")
    public String getPrincipal() {
        return principal;
    }

    public void setPrincipal(String principal) {
        this.principal = principal;
    }

    @ConfigurationProperty(order = 6, confidential = true,
            displayMessageKey = "credentials.display",
            helpMessageKey = "credentials.help")
    public GuardedString getCredentials() {
        return credentials;
    }

    public void setCredentials(GuardedString credentials) {
        this.credentials = credentials != null ? credentials.copy() : null;
    }

    @ConfigurationProperty(order = 7, required = true,
            displayMessageKey = "baseContexts.display",
            helpMessageKey = "baseContexts.help")
    public String[] getBaseContexts() {
        return baseContexts.clone();
    }

    public void setBaseContexts(String... baseContexts) {
        this.baseContexts = baseContexts.clone();
    }

    @ConfigurationProperty(order = 8,
            displayMessageKey = "passwordAttribute.display",
            helpMessageKey = "passwordAttribute.help")
    public String getPasswordAttribute() {
        return passwordAttribute;
    }

    public void setPasswordAttribute(String passwordAttribute) {
        this.passwordAttribute = passwordAttribute;
    }

    @ConfigurationProperty(order = 9,
            displayMessageKey = "accountObjectClasses.display",
            helpMessageKey = "accountObjectClasses.help")
    public String[] getAccountObjectClasses() {
        List<String> ldapClasses = accountConfig.getLdapClasses();
        return ldapClasses.toArray(new String[0]);
    }

    public void setAccountObjectClasses(String... accountObjectClasses) {
        accountConfig.setLdapClasses(Arrays.asList(accountObjectClasses));
    }

    @ConfigurationProperty(order = 10,
            displayMessageKey = "accountUserNameAttributes.display",
            helpMessageKey = "accountUserNameAttributes.help")
    public String[] getAccountUserNameAttributes() {
        List<String> shortNameLdapAttributes = accountConfig.getShortNameLdapAttributes();
        return shortNameLdapAttributes.toArray(new String[0]);
    }

    public void setAccountUserNameAttributes(String... accountUserNameAttributes) {
        accountConfig.setShortNameLdapAttributes(Arrays.asList(accountUserNameAttributes));
    }

    @ConfigurationProperty(order = 11,
            displayMessageKey = "userSearchScope.display",
            helpMessageKey = "userSearchScope.help")
    public String getUserSearchScope() {
        return userSearchScope.toString();
    }

    public void setUserSearchScope(String userSearchScope) {
        this.userSearchScope = SearchScope.valueOf(userSearchScope.toLowerCase());
    }

    @ConfigurationProperty(order = 12,
            displayMessageKey = "accountSearchFilter.display",
            helpMessageKey = "accountSearchFilter.help")
    public String getAccountSearchFilter() {
        return accountSearchFilter;
    }

    public void setAccountSearchFilter(String accountSearchFilter) {
        this.accountSearchFilter = accountSearchFilter;
    }

    @ConfigurationProperty(order = 13,
            displayMessageKey = "groupObjectClasses.display",
            helpMessageKey = "groupObjectClasses.help")
    public String[] getGroupObjectClasses() {
        List<String> ldapClasses = groupConfig.getLdapClasses();
        return ldapClasses.toArray(new String[0]);
    }

    public void setGroupObjectClasses(String... groupObjectClasses) {
        groupConfig.setLdapClasses(Arrays.asList(groupObjectClasses));
    }

    @ConfigurationProperty(order = 14,
            displayMessageKey = "groupNameAttributes.display",
            helpMessageKey = "groupNameAttributes.help")
    public String[] getGroupNameAttributes() {
        List<String> shortNameLdapAttributes = groupConfig.getShortNameLdapAttributes();
        return shortNameLdapAttributes.toArray(new String[0]);
    }

    public void setGroupNameAttributes(String... groupNameAttributes) {
        groupConfig.setShortNameLdapAttributes(Arrays.asList(groupNameAttributes));
    }

    @ConfigurationProperty(order = 15,
            displayMessageKey = "groupSearchScope.display",
            helpMessageKey = "groupSearchScope.help")
    public String getGroupSearchScope() {
        return groupSearchScope.toString();
    }

    public void setGroupSearchScope(String groupSearchScope) {
        this.groupSearchScope = SearchScope.valueOf(groupSearchScope.toLowerCase());
    }

    @ConfigurationProperty(order = 16,
            displayMessageKey = "groupMemberAttribute.display",
            helpMessageKey = "groupMemberAttribute.help")
    public String getGroupMemberAttribute() {
        return groupMemberAttribute;
    }

    public void setGroupMemberAttribute(String groupMemberAttribute) {
        this.groupMemberAttribute = groupMemberAttribute;
    }

    @ConfigurationProperty(order = 17,
            displayMessageKey = "maintainLdapGroupMembership.display",
            helpMessageKey = "maintainLdapGroupMembership.help")
    public boolean isMaintainLdapGroupMembership() {
        return maintainLdapGroupMembership;
    }

    public void setMaintainLdapGroupMembership(boolean maintainLdapGroupMembership) {
        this.maintainLdapGroupMembership = maintainLdapGroupMembership;
    }

    @ConfigurationProperty(order = 18,
            displayMessageKey = "maintainPosixGroupMembership.display",
            helpMessageKey = "maintainPosixGroupMembership.help")
    public boolean isMaintainPosixGroupMembership() {
        return maintainPosixGroupMembership;
    }

    public void setMaintainPosixGroupMembership(boolean maintainPosixGroupMembership) {
        this.maintainPosixGroupMembership = maintainPosixGroupMembership;
    }

    @ConfigurationProperty(order = 19,
            displayMessageKey = "addPrincipalToNewGroups.display",
            helpMessageKey = "addPrincipalToNewGroups.help")
    public boolean isAddPrincipalToNewGroups() {
        return addPrincipalToNewGroups;
    }

    public void setAddPrincipalToNewGroups(boolean addPrincipalToNewGroups) {
        this.addPrincipalToNewGroups = addPrincipalToNewGroups;
    }

    @ConfigurationProperty(order = 20,
            displayMessageKey = "anyObjectClasses.display",
            helpMessageKey = "anyObjectClasses.help")
    public String[] getAnyObjectClasses() {
        List<String> ldapClasses = anyObjectConfig.getLdapClasses();
        return ldapClasses.toArray(new String[0]);
    }

    public void setAnyObjectClasses(String... anyObjectClasses) {
        anyObjectConfig.setLdapClasses(Arrays.asList(anyObjectClasses));
    }

    @ConfigurationProperty(order = 21,
            displayMessageKey = "anyObjectNameAttributes.display",
            helpMessageKey = "anyObjectNameAttributes.help")
    public String[] getAnyObjectNameAttributes() {
        List<String> shortNameLdapAttributes = anyObjectConfig.getShortNameLdapAttributes();
        return shortNameLdapAttributes.toArray(new String[0]);
    }

    public void setAnyObjectNameAttributes(String... anyObjectNameAttributes) {
        anyObjectConfig.setShortNameLdapAttributes(Arrays.asList(anyObjectNameAttributes));
    }

    @ConfigurationProperty(order = 22,
            displayMessageKey = "anyObjectSearchFilter.display",
            helpMessageKey = "anyObjectSearchFilter.help")
    public String getAnyObjectSearchFilter() {
        return anyObjectSearchFilter;
    }

    public void setAnyObjectSearchFilter(String anyObjectSearchFilter) {
        this.anyObjectSearchFilter = anyObjectSearchFilter;
    }

    @ConfigurationProperty(order = 23,
            displayMessageKey = "anyObjectSearchScope.display",
            helpMessageKey = "anyObjectSearchScope.help")
    public String getAnyObjectSearchScope() {
        return anyObjectSearchScope.toString();
    }

    public void setAnyObjectSearchScope(String anyObjectSearchScope) {
        this.anyObjectSearchScope = SearchScope.valueOf(anyObjectSearchScope.toLowerCase());
    }

    @ConfigurationProperty(order = 24,
            displayMessageKey = "passwordHashAlgorithm.display",
            helpMessageKey = "passwordHashAlgorithm.help")
    public String getPasswordHashAlgorithm() {
        return passwordHashAlgorithm;
    }

    public void setPasswordHashAlgorithm(String passwordHashAlgorithm) {
        this.passwordHashAlgorithm = passwordHashAlgorithm;
    }

    @ConfigurationProperty(order = 25,
            displayMessageKey = "respectResourcePasswordPolicyChangeAfterReset.display",
            helpMessageKey = "respectResourcePasswordPolicyChangeAfterReset.help")
    public boolean isRespectResourcePasswordPolicyChangeAfterReset() {
        return respectResourcePasswordPolicyChangeAfterReset;
    }

    public void setRespectResourcePasswordPolicyChangeAfterReset(boolean respectResourcePasswordPolicyChangeAfterReset) {
        this.respectResourcePasswordPolicyChangeAfterReset = respectResourcePasswordPolicyChangeAfterReset;
    }

    @ConfigurationProperty(order = 26,
            displayMessageKey = "useVlvControls.display",
            helpMessageKey = "useVlvControls.help")
    public boolean isUseVlvControls() {
        return useVlvControls;
    }

    public void setUseVlvControls(boolean useVlvControls) {
        this.useVlvControls = useVlvControls;
    }

    @ConfigurationProperty(order = 27,
            displayMessageKey = "vlvSortAttribute.display",
            helpMessageKey = "vlvSortAttribute.help")
    public String getVlvSortAttribute() {
        return vlvSortAttribute;
    }

    public void setVlvSortAttribute(String vlvSortAttribute) {
        this.vlvSortAttribute = vlvSortAttribute;
    }

    @ConfigurationProperty(order = 28,
            displayMessageKey = "uidAttribute.display",
            helpMessageKey = "uidAttribute.help")
    public String getUidAttribute() {
        return uidAttribute;
    }

    public void setUidAttribute(final String uidAttribute) {
        this.uidAttribute = uidAttribute;
    }

    @ConfigurationProperty(order = 29,
            displayMessageKey = "gidAttribute.display",
            helpMessageKey = "gidAttribute.help")
    public String getGidAttribute() {
        return gidAttribute;
    }

    public void setGidAttribute(final String gidAttribute) {
        this.gidAttribute = gidAttribute;
    }

    @ConfigurationProperty(order = 30,
            displayMessageKey = "aoidAttribute.display",
            helpMessageKey = "aoidAttribute.help")
    public String getAoidAttribute() {
        return aoidAttribute;
    }

    public void setAoidAttribute(final String aoidAttribute) {
        this.aoidAttribute = aoidAttribute;
    }

    @ConfigurationProperty(order = 31,
            displayMessageKey = "readSchema.display",
            helpMessageKey = "readSchema.help")
    public boolean isReadSchema() {
        return readSchema;
    }

    public void setReadSchema(boolean readSchema) {
        this.readSchema = readSchema;
    }

    // Sync properties getters and setters.
    @ConfigurationProperty(order = 32, operations = { SyncOp.class },
            displayMessageKey = "baseContextsToSynchronize.display",
            helpMessageKey = "baseContextsToSynchronize.help")
    public String[] getBaseContextsToSynchronize() {
        return baseContextsToSynchronize.clone();
    }

    public void setBaseContextsToSynchronize(String... baseContextsToSynchronize) {
        this.baseContextsToSynchronize = baseContextsToSynchronize.clone();
    }

    @ConfigurationProperty(order = 33, operations = { SyncOp.class },
            displayMessageKey = "objectClassesToSynchronize.display",
            helpMessageKey = "objectClassesToSynchronize.help")
    public String[] getObjectClassesToSynchronize() {
        return objectClassesToSynchronize.clone();
    }

    public void setObjectClassesToSynchronize(String... objectClassesToSynchronize) {
        this.objectClassesToSynchronize = objectClassesToSynchronize.clone();
    }

    @ConfigurationProperty(order = 34, operations = { SyncOp.class },
            displayMessageKey = "attributesToSynchronize.display",
            helpMessageKey = "attributesToSynchronize.help")
    public String[] getAttributesToSynchronize() {
        return attributesToSynchronize.clone();
    }

    public void setAttributesToSynchronize(String... attributesToSynchronize) {
        this.attributesToSynchronize = attributesToSynchronize.clone();
    }

    @ConfigurationProperty(order = 35, operations = { SyncOp.class },
            displayMessageKey = "modifiersNamesToFilterOut.display",
            helpMessageKey = "modifiersNamesToFilterOut.help")
    public String[] getModifiersNamesToFilterOut() {
        return modifiersNamesToFilterOut.clone();
    }

    public void setModifiersNamesToFilterOut(String... modifiersNamesToFilterOut) {
        this.modifiersNamesToFilterOut = modifiersNamesToFilterOut.clone();
    }

    @ConfigurationProperty(order = 36, operations = { SyncOp.class },
            displayMessageKey = "accountSynchronizationFilter.display",
            helpMessageKey = "accountSynchronizationFilter.help")
    public String getAccountSynchronizationFilter() {
        return accountSynchronizationFilter;
    }

    public void setAccountSynchronizationFilter(String accountSynchronizationFilter) {
        this.accountSynchronizationFilter = accountSynchronizationFilter;
    }

    @ConfigurationProperty(order = 37, operations = { SyncOp.class },
            displayMessageKey = "changeLogBlockSize.display",
            helpMessageKey = "changeLogBlockSize.help")
    public int getChangeLogBlockSize() {
        return changeLogBlockSize;
    }

    public void setChangeLogBlockSize(int changeLogBlockSize) {
        this.changeLogBlockSize = changeLogBlockSize;
    }

    @ConfigurationProperty(order = 38, operations = { SyncOp.class },
            displayMessageKey = "changeNumberAttribute.display",
            helpMessageKey = "changeNumberAttribute.help")
    public String getChangeNumberAttribute() {
        return changeNumberAttribute;
    }

    public void setChangeNumberAttribute(String changeNumberAttribute) {
        this.changeNumberAttribute = changeNumberAttribute;
    }

    @ConfigurationProperty(order = 39, operations = { SyncOp.class },
            displayMessageKey = "changeLogContext.display",
            helpMessageKey = "changeNumberAttribute.help")
    public String getChangeLogContext() {
        return changeLogContext;
    }

    public void setChangeLogContext(String changeLogContext) {
        this.changeLogContext = changeLogContext;
    }

    @ConfigurationProperty(order = 39, operations = { SyncOp.class },
            displayMessageKey = "filterWithOrInsteadOfAnd.display",
            helpMessageKey = "filterWithOrInsteadOfAnd.help")
    public boolean isFilterWithOrInsteadOfAnd() {
        return filterWithOrInsteadOfAnd;
    }

    public void setFilterWithOrInsteadOfAnd(boolean filterWithOrInsteadOfAnd) {
        this.filterWithOrInsteadOfAnd = filterWithOrInsteadOfAnd;
    }

    @ConfigurationProperty(order = 40, operations = { SyncOp.class },
            displayMessageKey = "removeLogEntryObjectClassFromFilter.display",
            helpMessageKey = "removeLogEntryObjectClassFromFilter.help")
    public boolean isRemoveLogEntryObjectClassFromFilter() {
        return removeLogEntryObjectClassFromFilter;
    }

    public void setRemoveLogEntryObjectClassFromFilter(boolean removeLogEntryObjectClassFromFilter) {
        this.removeLogEntryObjectClassFromFilter = removeLogEntryObjectClassFromFilter;
    }

    @ConfigurationProperty(order = 41, operations = { SyncOp.class },
            displayMessageKey = "synchronizePasswords.display",
            helpMessageKey = "synchronizePasswords.help")
    public boolean isSynchronizePasswords() {
        return synchronizePasswords;
    }

    public void setSynchronizePasswords(boolean synchronizePasswords) {
        this.synchronizePasswords = synchronizePasswords;
    }

    @ConfigurationProperty(order = 42, operations = { SyncOp.class },
            displayMessageKey = "passwordAttributeToSynchronize.display",
            helpMessageKey = "passwordAttributeToSynchronize.help")
    public String getPasswordAttributeToSynchronize() {
        return passwordAttributeToSynchronize;
    }

    public void setPasswordAttributeToSynchronize(String passwordAttributeToSynchronize) {
        this.passwordAttributeToSynchronize = passwordAttributeToSynchronize;
    }

    @ConfigurationProperty(order = 43, operations = { SyncOp.class }, confidential = true,
            displayMessageKey = "passwordDecryptionKey.display",
            helpMessageKey = "passwordDecryptionKey.help")
    public GuardedByteArray getPasswordDecryptionKey() {
        return passwordDecryptionKey;
    }

    public void setPasswordDecryptionKey(GuardedByteArray passwordDecryptionKey) {
        this.passwordDecryptionKey = passwordDecryptionKey != null ? passwordDecryptionKey.
                copy() : null;
    }

    @ConfigurationProperty(order = 44, operations = { SyncOp.class }, confidential = true,
            displayMessageKey = "passwordDecryptionInitializationVector.display",
            helpMessageKey = "passwordDecryptionInitializationVector.help")
    public GuardedByteArray getPasswordDecryptionInitializationVector() {
        return passwordDecryptionInitializationVector;
    }

    public void setPasswordDecryptionInitializationVector(GuardedByteArray passwordDecryptionInitializationVector) {
        this.passwordDecryptionInitializationVector = passwordDecryptionInitializationVector != null
                ? passwordDecryptionInitializationVector.copy() : null;
    }

    @ConfigurationProperty(order = 45,
            displayMessageKey = "statusManagementClass.display",
            helpMessageKey = "statusManagementClass.help")
    public String getStatusManagementClass() {
        return statusManagementClass;
    }

    public void setStatusManagementClass(String statusManagementClass) {
        this.statusManagementClass = statusManagementClass;
    }

    @ConfigurationProperty(order = 46,
            displayMessageKey = "retrievePasswordsWithSearch.display",
            helpMessageKey = "retrievePasswordsWithSearch.help")
    public boolean getRetrievePasswordsWithSearch() {
        return retrievePasswordsWithSearch;
    }

    public void setRetrievePasswordsWithSearch(boolean retrievePasswordsWithSearch) {
        this.retrievePasswordsWithSearch = retrievePasswordsWithSearch;
    }

    @ConfigurationProperty(order = 47,
            displayMessageKey = "dnAttribute.display",
            helpMessageKey = "dnAttribute.help")
    public String getDnAttribute() {
        return dnAttribute;
    }

    public void setDnAttribute(String dnAttribute) {
        this.dnAttribute = dnAttribute;
    }

    @ConfigurationProperty(order = 48,
            displayMessageKey = "groupSearchFilter.display",
            helpMessageKey = "groupSearchFilter.help")
    public String getGroupSearchFilter() {
        return groupSearchFilter;
    }

    public void setGroupSearchFilter(String groupSearchFilter) {
        this.groupSearchFilter = groupSearchFilter;
    }

    @ConfigurationProperty(order = 49,
            displayMessageKey = "readTimeout.display",
            helpMessageKey = "readTimeout.help")
    public long getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(long readTimeout) {
        this.readTimeout = readTimeout;
    }

    @ConfigurationProperty(order = 50,
            displayMessageKey = "connectTimeout.display",
            helpMessageKey = "connectTimeout.help")
    public long getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(long connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    @ConfigurationProperty(order = 51,
            displayMessageKey = "syncStrategy.display",
            helpMessageKey = "syncStrategy.help")
    public String getSyncStrategy() {
        return syncStrategy;
    }

    public void setSyncStrategy(String syncStrategy) {
        this.syncStrategy = syncStrategy;
    }

    public Class<? extends LdapSyncStrategy> getSyncStrategyClass() {
        return syncStrategyClass;
    }

    protected Class<? extends LdapSyncStrategy> getFallbackSyncStrategyClass() {
        return fallbackSyncStrategyClass;
    }

    protected void setFallbackSyncStrategyClass(Class<? extends LdapSyncStrategy> fallbackSyncStrategyClass) {
        this.fallbackSyncStrategyClass = fallbackSyncStrategyClass;
    }

    protected Class<? extends LdapConnection> getConnectionClass() {
        return connectionClass;
    }

    protected void setConnectionClass(Class<? extends LdapConnection> connectionClass) {
        this.connectionClass = connectionClass;
    }

    // Getters and setters for configuration properties end here.
    public List<LdapName> getBaseContextsAsLdapNames() {
        if (baseContextsAsLdapNames == null) {
            List<LdapName> result = new ArrayList<>(baseContexts.length);
            try {
                for (String baseContext : baseContexts) {
                    result.add(new LdapName(baseContext));
                }
            } catch (InvalidNameException e) {
                throw new ConfigurationException(e);
            }
            baseContextsAsLdapNames = result;
        }
        return baseContextsAsLdapNames;
    }

    public List<LdapName> getBaseContextsToSynchronizeAsLdapNames() {
        if (baseContextsToSynchronizeAsLdapNames == null) {
            String[] source = LdapUtil.nullAsEmpty(baseContextsToSynchronize);
            List<LdapName> result = new ArrayList<>(source.length);
            try {
                for (String each : source) {
                    result.add(new LdapName(each));
                }
            } catch (InvalidNameException e) {
                throw new ConfigurationException(e);
            }
            baseContextsToSynchronizeAsLdapNames = result;
        }
        return baseContextsToSynchronizeAsLdapNames;
    }

    public Set<LdapName> getModifiersNamesToFilterOutAsLdapNames() {
        if (modifiersNamesToFilterOutAsLdapNames == null) {
            String[] source = LdapUtil.nullAsEmpty(modifiersNamesToFilterOut);
            Set<LdapName> result = new HashSet<>(source.length);
            try {
                for (String each : source) {
                    result.add(new LdapName(each));
                }
            } catch (InvalidNameException e) {
                throw new ConfigurationException(e);
            }
            modifiersNamesToFilterOutAsLdapNames = result;
        }
        return modifiersNamesToFilterOutAsLdapNames;
    }

    public Map<ObjectClass, ObjectClassMappingConfig> getObjectClassMappingConfigs() {
        Map<ObjectClass, ObjectClassMappingConfig> result = new HashMap<>();
        result.put(accountConfig.getObjectClass(), accountConfig);
        result.put(groupConfig.getObjectClass(), groupConfig);
        result.put(anyObjectConfig.getObjectClass(), anyObjectConfig);
        result.put(allConfig.getObjectClass(), allConfig);
        return result;
    }

    protected EqualsHashCodeBuilder createHashCodeBuilder() {
        EqualsHashCodeBuilder builder = new EqualsHashCodeBuilder();
        // Exposed configuration properties.
        builder.append(host);
        builder.append(port);
        builder.append(ssl);
        builder.append(failover);
        builder.append(principal);
        builder.append(credentials);
        for (String baseContext : baseContexts) {
            builder.append(baseContext);
        }
        builder.append(passwordAttribute);
        builder.append(accountSearchFilter);
        builder.append(groupMemberAttribute);
        builder.append(maintainLdapGroupMembership);
        builder.append(maintainPosixGroupMembership);
        builder.append(passwordHashAlgorithm);
        builder.append(respectResourcePasswordPolicyChangeAfterReset);
        builder.append(useVlvControls);
        builder.append(vlvSortAttribute);
        builder.append(readSchema);
        // Sync configuration properties.
        for (String baseContextToSynchronize : baseContextsToSynchronize) {
            builder.append(baseContextToSynchronize);
        }
        for (String objectClassToSynchronize : objectClassesToSynchronize) {
            builder.append(objectClassToSynchronize);
        }
        for (String attributeToSynchronize : attributesToSynchronize) {
            builder.append(attributeToSynchronize);
        }
        for (String modifiersNameToFilterOut : modifiersNamesToFilterOut) {
            builder.append(modifiersNameToFilterOut);
        }
        builder.append(accountSynchronizationFilter);
        builder.append(changeLogBlockSize);
        builder.append(changeNumberAttribute);
        builder.append(filterWithOrInsteadOfAnd);
        builder.append(removeLogEntryObjectClassFromFilter);
        builder.append(synchronizePasswords);
        builder.append(passwordAttributeToSynchronize);
        builder.append(passwordDecryptionKey);
        builder.append(passwordDecryptionInitializationVector);
        // Other state.
        builder.append(accountConfig);
        builder.append(groupConfig);
        builder.append(retrievePasswordsWithSearch);
        builder.append(groupSearchFilter);
        builder.append(connectTimeout);
        builder.append(readTimeout);
        return builder;
    }

    @Override
    public int hashCode() {
        return createHashCodeBuilder().hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof LdapConfiguration) {
            LdapConfiguration that = (LdapConfiguration) obj;
            if (this == that) {
                return true;
            }
            return this.createHashCodeBuilder().equals(that.createHashCodeBuilder());
        }
        return false;
    }
}
