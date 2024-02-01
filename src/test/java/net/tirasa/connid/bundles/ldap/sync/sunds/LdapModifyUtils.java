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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import net.tirasa.connid.bundles.ldap.LdapConnection;
import net.tirasa.connid.bundles.ldap.commons.LdapUtil;
import net.tirasa.connid.bundles.ldap.commons.LdifParser;
import net.tirasa.connid.bundles.ldap.commons.LdifParser.ChangeSeparator;
import net.tirasa.connid.bundles.ldap.commons.LdifParser.Line;
import net.tirasa.connid.bundles.ldap.commons.LdifParser.NameValue;
import net.tirasa.connid.bundles.ldap.commons.LdifParser.Separator;
import org.identityconnectors.common.logging.Log;

/**
 * A simple, and in no way complete, way to modify an LDAP server
 * based on an LDIF file.
 */
public class LdapModifyUtils {

    private static final Log LOG = Log.getLog(LdapModifyUtils.class);

    public static void modify(LdapConnection conn, String ldif) throws NamingException {
        LdifParser parser = new LdifParser(ldif);
        Iterator<Line> lines = parser.iterator();

        String dn = null;
        String changeType = null;

        Map<String, List<String>> added = new HashMap<>();
        Map<String, List<String>> deleted = new HashMap<>();
        Map<String, List<String>> modifyMap = null;

        String newRdn = null;
        String deleteOldRdn = "true";

        while (lines.hasNext()) {
            Line line = lines.next();
            if (line instanceof ChangeSeparator && dn != null) {
                performChange(conn, dn, changeType, added, deleted, newRdn,
                        deleteOldRdn);
                dn = null;
                changeType = null;
                added.clear();
                deleted.clear();
                modifyMap = null;
                newRdn = null;
                deleteOldRdn = "true";
                continue;
            }
            if (dn == null) {
                NameValue nameValue = (NameValue) line;
                if (!"dn".equalsIgnoreCase(nameValue.getName())) {
                    throw new IllegalArgumentException();
                }
                dn = nameValue.getValue();
                continue;
            }
            if (changeType == null) {
                NameValue nameValue = (NameValue) line;
                if (!"changeType".equalsIgnoreCase(nameValue.getName())) {
                    throw new IllegalArgumentException();
                }
                changeType = nameValue.getValue();
                continue;
            }
            if ("add".equalsIgnoreCase(changeType)) {
                NameValue nameValue = (NameValue) line;
                List<String> values = added.get(nameValue.getName());
                if (values == null) {
                    values = new ArrayList<>();
                    added.put(nameValue.getName(), values);
                }
                values.add(nameValue.getValue());
            } else if ("modify".equalsIgnoreCase(changeType)) {
                if (line instanceof Separator) {
                    modifyMap = null;
                    continue;
                }
                if (modifyMap == null) {
                    NameValue nameValue = (NameValue) line;
                    String op = nameValue.getName();
                    if ("add".equalsIgnoreCase(op)) {
                        modifyMap = added;
                    } else if ("delete".equalsIgnoreCase(op)) {
                        modifyMap = deleted;
                    } else {
                        throw new IllegalArgumentException();
                    }
                    continue;
                } else {
                    NameValue nameValue = (NameValue) line;
                    List<String> values = modifyMap.get(nameValue.getName());
                    if (values == null) {
                        values = new ArrayList<>();
                        modifyMap.put(nameValue.getName(), values);
                    }
                    values.add(nameValue.getValue());
                }
            } else if ("modrdn".equalsIgnoreCase(changeType)) {
                NameValue nameValue = (NameValue) line;
                if ("newRdn".equalsIgnoreCase(nameValue.getName())) {
                    newRdn = nameValue.getValue();
                } else if ("deleteOldRdn".equalsIgnoreCase(nameValue.getName())) {
                    deleteOldRdn = nameValue.getValue().toLowerCase(Locale.US);
                }
            }
        }
    }

    private static void performChange(LdapConnection conn, String dn, String changeType,
            Map<String, List<String>> added, Map<String, List<String>> deleted, String newRdn, String deleteOldRdn)
            throws NamingException {

        if ("add".equalsIgnoreCase(changeType)) {
            BasicAttributes attrs = new BasicAttributes();
            for (Entry<String, List<String>> entry : added.entrySet()) {
                Attribute attr = new BasicAttribute(entry.getKey());
                for (String each : entry.getValue()) {
                    attr.add(each);
                }
                attrs.put(attr);
            }
            LdapName newName = LdapUtil.quietCreateLdapName(dn);
            LOG.ok("Creating context {0} with attributes {1}", newName, attrs);
            String container = newName.getPrefix(newName.size() - 1).toString();
            Rdn rdn = newName.getRdn(newName.size() - 1);
            LdapContext containerCtx = (LdapContext) conn.getInitialContext().
                    lookup(container);
            containerCtx.createSubcontext(rdn.toString(), attrs);
        } else if ("modify".equalsIgnoreCase(changeType)) {
            List<ModificationItem> modItems = new ArrayList<>();
            addModificationItems(DirContext.ADD_ATTRIBUTE, added, modItems);
            addModificationItems(DirContext.REMOVE_ATTRIBUTE, deleted, modItems);
            LOG.ok("Modifying context {0} with attributes {1}", dn, modItems);
            conn.getInitialContext().modifyAttributes(dn, modItems.toArray(new ModificationItem[modItems.size()]));
        } else if ("delete".equalsIgnoreCase(changeType)) {
            LOG.ok("Deleting context {0}");
            conn.getInitialContext().destroySubcontext(dn);
        } else if ("modrdn".equalsIgnoreCase(changeType)) {
            LdapName oldName = LdapUtil.quietCreateLdapName(dn);
            LdapName newName = (LdapName) oldName.getPrefix(oldName.size() - 1);
            newName.add(newRdn);
            LOG.ok("Renaming context {0} to {1}", oldName, newName);
            LdapContext ctx = conn.getInitialContext().newInstance(null);
            try {
                ctx.addToEnvironment("java.naming.ldap.deleteRDN", deleteOldRdn);
                ctx.rename(oldName, newName);
            } finally {
                ctx.close();
            }
        }
    }

    private static void addModificationItems(
            int operation, Map<String, List<String>> map, List<ModificationItem> toList) {

        for (Entry<String, List<String>> entry : map.entrySet()) {
            Attribute attr = new BasicAttribute(entry.getKey());
            for (String each : entry.getValue()) {
                attr.add(each);
            }
            toList.add(new ModificationItem(operation, attr));
        }
    }
}
