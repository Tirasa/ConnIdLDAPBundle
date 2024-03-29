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
package net.tirasa.connid.bundles.ldap.schema;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import org.identityconnectors.common.security.GuardedString;
import org.junit.jupiter.api.Test;

public class GuardedPasswordAttributeTests {

    @Test
    public void access() throws NamingException {
        String PASSWORD = "\u011b\u0161\u010d\u0159\u017e\u00fd\u00e1\u00ed\u00e9"; // Czech characters ;-)

        GuardedPasswordAttribute pwdAttr =
                GuardedPasswordAttribute.create("userPassword", new GuardedString(PASSWORD.toCharArray()));
        final Attribute[] attribute = { null };

        pwdAttr.access(passwordAttribute -> {
            assertEquals("userPassword", passwordAttribute.getID());
            try {
                assertEquals(PASSWORD, new String((byte[]) passwordAttribute.get(), StandardCharsets.UTF_8));
            } catch (NamingException e) {
                throw new RuntimeException(e);
            }
            attribute[0] = passwordAttribute;
        });
        assertEquals(1, attribute[0].size());
        byte[] value = (byte[]) attribute[0].get();
        for (int i = 0; i < value.length; i++) {
            assertEquals((byte) 0, value[i]);
        }
    }

    @Test
    public void empty() {
        GuardedPasswordAttribute pwdAttr = GuardedPasswordAttribute.create("userPassword");
        pwdAttr.access(passwordAttribute -> assertEquals(0, passwordAttribute.size()));
    }
}
