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
package net.tirasa.connid.bundles.ldap.commons;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import net.tirasa.connid.bundles.ldap.LdapConnection;
import net.tirasa.connid.bundles.ldap.commons.GroupHelper.GroupMembership;
import net.tirasa.connid.bundles.ldap.search.LdapSearches;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.framework.common.exceptions.ConnectorException;

public abstract class LdapModifyOperation {

    protected final LdapConnection conn;

    protected final GroupHelper groupHelper;

    public LdapModifyOperation(LdapConnection conn) {
        this.conn = conn;
        groupHelper = new GroupHelper(conn);
    }

    protected final void hashPassword(final Attribute passwordAttr, final String entryDN) {
        String hashAlgorithm = conn.getConfiguration().getPasswordHashAlgorithm();
        if (StringUtil.isBlank(hashAlgorithm) || "NONE".equalsIgnoreCase(hashAlgorithm)) {
            return;
        }
        try {
            byte[] password = (byte[]) passwordAttr.get();
            if (password != null) {
                String newPassword = hashBytes(password, hashAlgorithm, entryDN == null ? 0 : entryDN.hashCode());
                passwordAttr.clear();
                passwordAttr.add(newPassword);
            }
        } catch (NamingException e) {
            throw new ConnectorException(e);
        }
    }

    private String hashBytes(final byte[] plain, final String algorithm, final long randSeed) {
        String plainPassword = new String(plain);
        if (plainPassword.startsWith("{")) {
            String digest = plainPassword.substring(1, plainPassword.indexOf('}'));
            if (digest != null && algorithm.equalsIgnoreCase(digest)) {
                return plainPassword;
            }
        }

        MessageDigest digest = null;
        try {
            if (algorithm.equalsIgnoreCase("SSHA") || algorithm.equalsIgnoreCase("SHA")) {
                digest = MessageDigest.getInstance("SHA-1");
            } else if (algorithm.equalsIgnoreCase("SMD5") || algorithm.equalsIgnoreCase("MD5")) {
                digest = MessageDigest.getInstance("MD5");
            } else if (algorithm.equalsIgnoreCase("SSHA256") || algorithm.equalsIgnoreCase("SHA256")) {
                digest = MessageDigest.getInstance("SHA-256");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new ConnectorException("Could not find MessageDigest algorithm (" + algorithm + ") implementation");
        }
        if (digest == null) {
            throw new ConnectorException("Unsupported hash algorithm: " + algorithm);
        }

        byte[] salt = {};

        if (algorithm.equalsIgnoreCase("SSHA256") || algorithm.equalsIgnoreCase("SSHA") || algorithm.equalsIgnoreCase("SMD5")) {
            Random rand = new Random();
            rand.setSeed(System.currentTimeMillis() + randSeed);
            // A RSA whitepaper <http://www.rsasecurity.com/solutions/developers/whitepapers/Article3-PBE.pdf>
            // suggested the salt length be the same as the output of the
            // hash function being used. The adapter uses the length of the input,
            // hoping that it is close enough an approximation.
            salt = new byte[8];
            rand.nextBytes(salt);
        }

        digest.reset();
        digest.update(plain);
        digest.update(salt);
        byte[] hash = digest.digest();

        byte[] hashPlusSalt = new byte[hash.length + salt.length];
        System.arraycopy(hash, 0, hashPlusSalt, 0, hash.length);
        System.arraycopy(salt, 0, hashPlusSalt, hash.length, salt.length);

        StringBuilder result = new StringBuilder(algorithm.length() + hashPlusSalt.length);
        result.append('{');
        result.append(algorithm);
        result.append('}');
        result.append(Base64.getEncoder().encodeToString(hashPlusSalt));

        return result.toString();
    }

    protected static Set<String> getAttributeValues(
            final String attrName, final LdapName entryDN, final Attributes attrs) {

        final Set<String> result = new HashSet<>();
        if (entryDN != null && !entryDN.isEmpty()) {
            Rdn rdn = entryDN.getRdn(entryDN.size() - 1);
            LdapUtil.addStringAttrValues(rdn.toAttributes(), attrName, result);
        }
        Attribute attr = attrs.get(attrName);
        if (attr != null) {
            try {
                NamingEnumeration<?> attrEnum = attr.getAll();
                while (attrEnum.hasMoreElements()) {
                    result.add((String) attrEnum.nextElement());
                }
            } catch (NamingException e) {
                throw new ConnectorException(e);
            }
            return result;
        }
        // If we got here, the attribute was not in the Attributes instance. So if the
        // result is empty, that means the attribute is not present in either
        // the entry DN or the attribute set.
        return result.isEmpty() ? null : result;
    }

    protected final String getFirstPosixRefAttr(final String entryDN, final Set<String> posixRefAttrs) {
        if (CollectionUtil.isEmpty(posixRefAttrs)) {
            throw new ConnectorException(
                    conn.format("cannotAddToPosixGroup", null, entryDN, GroupHelper.getPosixRefAttribute()));
        }
        return Collections.min(posixRefAttrs);
    }

    /**
     * Holds the POSIX ref attributes and the respective group memberships. Retrieves them lazily so that they are only
     * retrieved once, when they are needed.
     */
    public final class PosixGroupMember {

        private final String entryDN;

        private LdapEntry entry;

        private Set<String> posixRefAttrs;

        private Set<GroupMembership> posixGroupMemberships;

        public PosixGroupMember(String entryDN) {
            this.entryDN = entryDN;
        }

        public Set<GroupMembership> getPosixGroupMemberships() {
            if (posixGroupMemberships == null) {
                posixGroupMemberships = groupHelper.getPosixGroupMemberships(
                        getPosixRefAttributes());
            }
            return posixGroupMemberships;
        }

        public Set<GroupMembership> getPosixGroupMembershipsByAttrs(final Set<String> posixRefAttrs) {
            Set<GroupMembership> result = new HashSet<>();
            for (GroupMembership member : getPosixGroupMemberships()) {
                if (posixRefAttrs.contains(member.getMemberRef())) {
                    result.add(member);
                }
            }
            return result;
        }

        public Set<GroupMembership> getPosixGroupMembershipsByGroups(final List<String> groupDNs) {
            Set<LdapName> groupNames = new HashSet<>();
            for (String groupDN : groupDNs) {
                groupNames.add(LdapUtil.quietCreateLdapName(groupDN));
            }
            Set<GroupMembership> result = new HashSet<>();
            for (GroupMembership member : getPosixGroupMemberships()) {
                if (groupNames.contains(LdapUtil.quietCreateLdapName(member.getGroupDN()))) {
                    result.add(member);
                }
            }
            return result;
        }

        public Set<String> getPosixRefAttributes() {
            if (posixRefAttrs == null) {
                posixRefAttrs = getAttributeValues(GroupHelper.getPosixRefAttribute(), null,
                        getLdapEntry().getAttributes());
            }
            return posixRefAttrs;
        }

        private LdapEntry getLdapEntry() {
            if (entry == null) {
                entry = LdapSearches.getEntry(
                        conn, LdapUtil.quietCreateLdapName(entryDN), GroupHelper.getPosixRefAttribute());
            }
            return entry;
        }
    }
}
