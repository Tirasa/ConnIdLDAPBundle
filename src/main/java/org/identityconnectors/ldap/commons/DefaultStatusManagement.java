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
 * http://IdentityConnectors.dev.java.net/legal/license.txt
 * See the License for the specific language governing permissions and limitations 
 * under the License. 
 * 
 * When distributing the Covered Code, include this CDDL Header Notice in each file
 * and include the License file at identityconnectors/legal/license.txt.
 * If applicable, add the following below this CDDL Header, with the fields 
 * enclosed by brackets [] replaced by your own identifying information: 
 * "Portions Copyrighted [year] [name of copyright owner]"
 * ====================
 */
package org.identityconnectors.ldap.commons;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.naming.directory.Attributes;

public class DefaultStatusManagement extends StatusManagement {

    @Override
    public void setStatus(
            final boolean status,
            final Attributes attributes,
            final List<String> posixGroups,
            final List<String> ldapGroups) {
        // do nothing by default
    }

    @Override
    public Boolean getStatus(
            final Attributes attributes,
            final List<String> posixGroups,
            final List<String> ldapGroups) {
        return null;
    }

    @Override
    public Set<String> getOperationalAttributes() {
        return new HashSet<String>();
    }
}
