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
package net.tirasa.connid.bundles.ldap.sync.sunds;

import java.util.Collections;

import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import net.tirasa.connid.bundles.ldap.LdapConnection;
import net.tirasa.connid.bundles.ldap.commons.LdapUtil;
import net.tirasa.connid.bundles.ldap.sync.GenericChangeLogSyncStrategy;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributesAccessor;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.SyncDelta;
import org.identityconnectors.framework.common.objects.SyncDeltaBuilder;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;

/**
 * An implementation of the sync operation based on the retro change log
 * plugin of Sun Directory Server.
 */
public class SunDSChangeLogSyncStrategy extends GenericChangeLogSyncStrategy {

    private ChangeLogAttributes changeLogAttrs;

    public SunDSChangeLogSyncStrategy(LdapConnection conn) {
        super(conn);
    }

    @Override
    public SyncToken getLatestSyncToken(ObjectClass oclass) {
        return new SyncToken(getChangeLogAttributes().getLastChangeNumber());
    }

    @Override
    protected SyncDelta createDeletionSyncDelta(
            final SyncDeltaBuilder syncDeltaBuilder,
            final String targetDN,
            final ObjectClass oclass,
            final AttributesAccessor inputAttrs)
            throws InvalidNameException {

        LOG.ok("Creating sync delta for deleted entry {0}", inputAttrs.findString("targetEntryUUID"));

        String uidAttr = conn.getSchema().getLdapUidAttribute(oclass);

        Uid deletedUid;
        if (LDAP_DN_ATTRIBUTES.contains(uidAttr)) {
            deletedUid = createUid(uidAttr, targetDN);
        } else if ("entryUUID".equalsIgnoreCase(uidAttr)) {
            deletedUid = new Uid(inputAttrs.findString("targetEntryUUID"));
        } else {
            // ever fallback to dn without throwing any exception more reliable
            deletedUid = new Uid(targetDN);
        }
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

    @Override
    protected int getStartChangeNumber(final SyncToken lastToken) {
        Integer lastTokenValue = lastToken != null ? (Integer) lastToken.getValue() : null;
        if (lastTokenValue == null) {
            return getChangeLogAttributes().getFirstChangeNumber();
        }
        return lastTokenValue + 1; // Since the token value is the last value.
    }

    ChangeLogAttributes getChangeLogAttributes() {
        if (changeLogAttrs == null) {
            try {
                Attributes attrs = conn.getInitialContext().getAttributes("",
                        new String[] { "changeLog", "firstChangeNumber", "lastChangeNumber" });
                String changeLog = LdapUtil.getStringAttrValue(attrs, "changeLog");
                String firstChangeNumber = LdapUtil.getStringAttrValue(attrs, "firstChangeNumber");
                String lastChangeNumber = LdapUtil.getStringAttrValue(attrs, "lastChangeNumber");
                if (changeLog == null || firstChangeNumber == null | lastChangeNumber == null) {
                    throw new ConnectorException("Unable to locate the replication change log.\n"
                            + "From the admin console please verify that the "
                            + "change log is enabled under Configuration: "
                            + "Replication: Supplier Settings and that the Retro "
                            + "Change Log Plugin is enabled under Configuration: "
                            + "Plug-ins: Retro Change Log Plugin");
                }
                changeLogAttrs = new ChangeLogAttributes(
                        changeLog,
                        convertToInt(firstChangeNumber, 0),
                        convertToInt(lastChangeNumber, 0));
            } catch (NamingException e) {
                throw new ConnectorException(e);
            }
        }
        return changeLogAttrs;
    }
}
