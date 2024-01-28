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
package net.tirasa.connid.bundles.ldap.modify;

import java.util.List;
import java.util.Set;
import javax.naming.NamingException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.Uid;
import net.tirasa.connid.bundles.ldap.LdapConnection;
import net.tirasa.connid.bundles.ldap.commons.LdapModifyOperation;
import net.tirasa.connid.bundles.ldap.commons.GroupHelper.GroupMembership;
import net.tirasa.connid.bundles.ldap.search.LdapSearches;

public class LdapDelete extends LdapModifyOperation {

    protected final ObjectClass oclass;

    protected final Uid uid;

    public LdapDelete(LdapConnection conn, ObjectClass oclass, Uid uid) {
        super(conn);
        this.oclass = oclass;
        this.uid = uid;
    }

    public void execute() {
        String entryDN = LdapSearches.getEntryDN(conn, oclass, uid);

        if (conn.getConfiguration().isMaintainLdapGroupMembership()) {
            List<String> ldapGroups = groupHelper.getLdapGroups(entryDN);
            groupHelper.removeLdapGroupMemberships(entryDN, ldapGroups);
        }

        if (conn.getConfiguration().isMaintainPosixGroupMembership()) {
            PosixGroupMember posixMember = new PosixGroupMember(entryDN);
            Set<GroupMembership> memberships = posixMember.getPosixGroupMemberships();
            groupHelper.removePosixGroupMemberships(memberships);
        }

        try {
            conn.getInitialContext().destroySubcontext(entryDN);
        } catch (NamingException e) {
            throw new ConnectorException(e);
        }
    }
}
