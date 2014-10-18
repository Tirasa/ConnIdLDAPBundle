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

public class AttributeMappingConfig {

    private final String fromAttribute;

    private final String toAttribute;

    public AttributeMappingConfig(String fromAttribute, String toAttribute) {
        this.fromAttribute = fromAttribute;
        this.toAttribute = toAttribute;
    }

    public String getFromAttribute() {
        return fromAttribute;
    }

    public String getToAttribute() {
        return toAttribute;
    }

    @Override
    public int hashCode() {
        return fromAttribute.hashCode() + toAttribute.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof AttributeMappingConfig) {
            AttributeMappingConfig that = (AttributeMappingConfig) o;
            if (!this.fromAttribute.equals(that.fromAttribute)) {
                return false;
            }
            if (!this.toAttribute.equals(that.toAttribute)) {
                return false;
            }
            return true;
        }
        return false;
    }
}
