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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import javax.naming.directory.Attribute;
import javax.naming.directory.BasicAttribute;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.common.security.SecurityUtil;

public abstract class GuardedPasswordAttribute {

    public static GuardedPasswordAttribute create(final String attrName, final GuardedString password) {
        return new Simple(attrName, password);
    }

    public static GuardedPasswordAttribute create(final String attrName) {
        return new Empty(attrName);
    }

    public abstract void access(Accessor accessor);

    public interface Accessor {

        void access(Attribute passwordAttribute);
    }

    public static class Simple extends GuardedPasswordAttribute {

        protected final String attrName;

        protected final GuardedString password;

        protected Simple(final String attrName, final GuardedString password) {
            super();

            this.attrName = attrName;
            this.password = password;
        }

        @Override
        public void access(final Accessor accessor) {
            password.access(new GuardedString.Accessor() {

                @Override
                public void access(final char[] clearChars) {
                    // TODO this is still not good enough. Need a simple and reliable
                    // way to convert UTF-16 to UTF-8 bytes.
                    CharBuffer charBuf = CharBuffer.wrap(clearChars);
                    ByteBuffer byteBuf = Charset.forName("UTF-8").encode(charBuf);
                    try {
                        byteBuf.rewind();
                        byte[] bytes = new byte[byteBuf.limit()];
                        byteBuf.get(bytes);
                        try {
                            BasicAttribute attr = new BasicAttribute(attrName, bytes);
                            accessor.access(attr);
                        } finally {
                            SecurityUtil.clear(bytes);
                        }
                    } finally {
                        byteBuf.rewind();
                        while (byteBuf.remaining() > 0) {
                            byteBuf.put((byte) 0);
                        }
                    }
                }
            });
        }
    }

    public static class Empty extends GuardedPasswordAttribute {

        protected final String attrName;

        protected Empty(final String attrName) {
            super();

            this.attrName = attrName;
        }

        @Override
        public void access(final Accessor accessor) {
            accessor.access(new BasicAttribute(attrName));
        }
    }
}
