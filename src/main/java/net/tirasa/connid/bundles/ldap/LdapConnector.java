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

import java.util.Set;
import net.tirasa.connid.bundles.ldap.modify.LdapCreate;
import net.tirasa.connid.bundles.ldap.modify.LdapDelete;
import net.tirasa.connid.bundles.ldap.modify.LdapUpdate;
import net.tirasa.connid.bundles.ldap.search.LdapFilter;
import net.tirasa.connid.bundles.ldap.search.LdapFilterTranslator;
import net.tirasa.connid.bundles.ldap.search.LdapSearch;
import net.tirasa.connid.bundles.ldap.sync.LdapSyncStrategy;
import net.tirasa.connid.bundles.ldap.sync.sunds.SunDSChangeLogSyncStrategy;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeDelta;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.PoolableConnector;
import org.identityconnectors.framework.spi.operations.AuthenticateOp;
import org.identityconnectors.framework.spi.operations.CreateOp;
import org.identityconnectors.framework.spi.operations.DeleteOp;
import org.identityconnectors.framework.spi.operations.ResolveUsernameOp;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.SyncOp;
import org.identityconnectors.framework.spi.operations.TestOp;
import org.identityconnectors.framework.spi.operations.UpdateAttributeValuesOp;
import org.identityconnectors.framework.spi.operations.UpdateDeltaOp;
import org.identityconnectors.framework.spi.operations.UpdateOp;

@ConnectorClass(configurationClass = LdapConfiguration.class, displayNameKey = "LdapConnector")
public class LdapConnector implements
        TestOp, PoolableConnector, SchemaOp, SearchOp<LdapFilter>,
        AuthenticateOp, ResolveUsernameOp, CreateOp, UpdateOp, UpdateDeltaOp, UpdateAttributeValuesOp,
        DeleteOp, SyncOp {

    private static final Log LOG = Log.getLog(LdapConnector.class);

    /**
     * The configuration for this connector instance.
     */
    protected LdapConfiguration config;

    /**
     * The connection to the LDAP server.
     */
    protected LdapConnection conn;

    protected LdapSyncStrategy syncStrategy;

    @Override
    public Configuration getConfiguration() {
        return config;
    }

    @Override
    public void init(Configuration cfg) {
        config = (LdapConfiguration) cfg;
        config.validate();
        Class<? extends LdapSyncStrategy> syncStrategyClass = config.getSyncStrategyClass();
        Class<? extends LdapConnection> connectionClass = config.getConnectionClass();
        
        try {
            conn = connectionClass.getConstructor(LdapConfiguration.class).newInstance(config);
        } catch (Exception e) {
            LOG.error(e, "Could not instantiate the configured connection class implementation {0}, reverting to {1}",
                    connectionClass.getName(), LdapConnection.class.getName());
            conn = new LdapConnection(config);
        }

        try {
            syncStrategy = syncStrategyClass.getConstructor(connectionClass).newInstance(conn);
        } catch (Exception e) {
            Class<? extends LdapSyncStrategy> fallbackSyncStrategyClass = config.getFallbackSyncStrategyClass();
            LOG.error(e, "Could not instantiate the configured {0} implementation, reverting to {1}",
                    LdapSyncStrategy.class.getName(), fallbackSyncStrategyClass.getName());
            try {
                syncStrategy = config.getFallbackSyncStrategyClass().getConstructor(connectionClass)
                        .newInstance(conn);
            } catch (Exception ex) {
                LOG.error(e, "Could not instantiate the configured fallback {0} imeplementation, falling back to {1}",
                        LdapSyncStrategy.class.getName(), SunDSChangeLogSyncStrategy.class);
                syncStrategy = new SunDSChangeLogSyncStrategy(conn);
            }
        }
    }

    @Override
    public void dispose() {
        conn.close();
    }

    @Override
    public void test() {
        conn.test();
    }

    @Override
    public void checkAlive() {
        conn.checkAlive();
    }

    @Override
    public Schema schema() {
        return conn.getSchema().schema();
    }

    @Override
    public Uid authenticate(
            final ObjectClass objectClass,
            final String username,
            final GuardedString password,
            final OperationOptions options) {

        return new LdapAuthenticate(conn, objectClass, username, options).authenticate(password);
    }

    @Override
    public Uid resolveUsername(
            final ObjectClass objectClass,
            final String username,
            final OperationOptions options) {

        return new LdapAuthenticate(conn, objectClass, username, options).resolveUsername();
    }

    @Override
    public FilterTranslator<LdapFilter> createFilterTranslator(
            final ObjectClass oclass,
            final OperationOptions options) {
        return new LdapFilterTranslator(conn.getSchema(), oclass);
    }

    @Override
    public void executeQuery(
            final ObjectClass oclass,
            final LdapFilter query,
            final ResultsHandler handler,
            final OperationOptions options) {
        new LdapSearch(conn, oclass, query, handler, options).execute();
    }

    @Override
    public Uid create(
            final ObjectClass oclass,
            final Set<Attribute> attrs,
            final OperationOptions options) {
        return new LdapCreate(conn, oclass, attrs, options).execute();
    }

    @Override
    public void delete(
            final ObjectClass oclass,
            final Uid uid,
            final OperationOptions options) {
        new LdapDelete(conn, oclass, uid).execute();
    }

    @Override
    public Uid update(
            final ObjectClass oclass,
            final Uid uid,
            final Set<Attribute> replaceAttributes,
            final OperationOptions options) {
        return new LdapUpdate(conn, oclass, uid).update(replaceAttributes);
    }

    @Override
    public Set<AttributeDelta> updateDelta(
            final ObjectClass oclass,
            final Uid uid,
            final Set<AttributeDelta> modifications,
            final OperationOptions options) {
        return new LdapUpdate(conn, oclass, uid).updateDelta(modifications);
    }

    @Override
    public Uid addAttributeValues(
            final ObjectClass oclass,
            final Uid uid,
            final Set<Attribute> valuesToAdd,
            final OperationOptions options) {
        return new LdapUpdate(conn, oclass, uid).addAttributeValues(valuesToAdd);
    }

    @Override
    public Uid removeAttributeValues(
            final ObjectClass oclass,
            final Uid uid,
            final Set<Attribute> valuesToRemove,
            final OperationOptions options) {
        return new LdapUpdate(conn, oclass, uid).removeAttributeValues(valuesToRemove);
    }

    @Override
    public SyncToken getLatestSyncToken(final ObjectClass oclass) {
        return syncStrategy.getLatestSyncToken(oclass);
    }

    @Override
    public void sync(
            final ObjectClass oclass,
            final SyncToken token,
            final SyncResultsHandler handler,
            final OperationOptions options) {
        syncStrategy.sync(token, handler, options, oclass);
    }
}
