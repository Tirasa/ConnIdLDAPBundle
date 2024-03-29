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

import static org.junit.jupiter.api.Assertions.assertEquals;

import net.tirasa.connid.bundles.ldap.commons.LdapEntry;

import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import org.junit.jupiter.api.Test;

public class LdapEntryTests {

    @Test
    public void entryDNAttribute() throws Exception {
        final String NAME = "uid=admin";
        final String BASE = "dc=example,dc=com";
        final String ENTRY_DN = NAME + "," + BASE;
        final String OTHER_ENTRY_DN = "uid=nothing,dc=example,dc=com";

        BasicAttributes attrs = new BasicAttributes(false);
        attrs.put(new BasicAttribute("entryDN", OTHER_ENTRY_DN));
        attrs.put(new BasicAttribute("cn", "Common Name"));
        LdapEntry entry = LdapEntry.create(NAME + "," + BASE, attrs);

        assertEquals("Common Name", entry.getAttributes().get("cn").get());
        assertEquals(ENTRY_DN, entry.getAttributes().get("dn").get());
        assertEquals(ENTRY_DN, entry.getAttributes().get("entryDN").get());
    }
}
