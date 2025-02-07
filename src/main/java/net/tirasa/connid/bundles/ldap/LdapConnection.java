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

import com.sun.jndi.ldap.ctl.PasswordExpiredResponseControl;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;
import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import net.tirasa.connid.bundles.ldap.commons.LdapConstants;
import net.tirasa.connid.bundles.ldap.commons.LdapNativeSchema;
import net.tirasa.connid.bundles.ldap.commons.LdapUtil;
import net.tirasa.connid.bundles.ldap.commons.ServerNativeSchema;
import net.tirasa.connid.bundles.ldap.commons.StaticNativeSchema;
import net.tirasa.connid.bundles.ldap.schema.LdapSchema;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.Pair;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.common.security.GuardedString.Accessor;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorSecurityException;
import org.identityconnectors.framework.common.exceptions.InvalidCredentialException;
import org.identityconnectors.framework.common.exceptions.PasswordExpiredException;

public class LdapConnection {

    // TODO: SASL authentication, "dn:entryDN" user name.
    // The LDAP attributes with a byte array syntax.
    private static final Set<String> LDAP_BINARY_SYNTAX_ATTRS;
    // The LDAP attributes which require the binary option for transfer.

    private static final Set<String> LDAP_BINARY_OPTION_ATTRS;

    static {
        // Cf. http://java.sun.com/products/jndi/tutorial/ldap/misc/attrs.html.
        LDAP_BINARY_SYNTAX_ATTRS = CollectionUtil.newCaseInsensitiveSet();
        LDAP_BINARY_SYNTAX_ATTRS.add("audio");
        LDAP_BINARY_SYNTAX_ATTRS.add("jpegPhoto");
        LDAP_BINARY_SYNTAX_ATTRS.add("photo");
        LDAP_BINARY_SYNTAX_ATTRS.add("personalSignature");
        LDAP_BINARY_SYNTAX_ATTRS.add("userPassword");
        LDAP_BINARY_SYNTAX_ATTRS.add("userCertificate");
        LDAP_BINARY_SYNTAX_ATTRS.add("caCertificate");
        LDAP_BINARY_SYNTAX_ATTRS.add("authorityRevocationList");
        LDAP_BINARY_SYNTAX_ATTRS.add("deltaRevocationList");
        LDAP_BINARY_SYNTAX_ATTRS.add("certificateRevocationList");
        LDAP_BINARY_SYNTAX_ATTRS.add("crossCertificatePair");
        LDAP_BINARY_SYNTAX_ATTRS.add("x500UniqueIdentifier");
        LDAP_BINARY_SYNTAX_ATTRS.add("supportedAlgorithms");
        // Java serialized objects.
        LDAP_BINARY_SYNTAX_ATTRS.add("javaSerializedData");
        // These seem to only be present in Active Directory.
        LDAP_BINARY_SYNTAX_ATTRS.add("thumbnailPhoto");
        LDAP_BINARY_SYNTAX_ATTRS.add("thumbnailLogo");

        // Cf. RFC 4522 and RFC 4523.
        LDAP_BINARY_OPTION_ATTRS = CollectionUtil.newCaseInsensitiveSet();
        LDAP_BINARY_OPTION_ATTRS.add("userCertificate");
        LDAP_BINARY_OPTION_ATTRS.add("caCertificate");
        LDAP_BINARY_OPTION_ATTRS.add("authorityRevocationList");
        LDAP_BINARY_OPTION_ATTRS.add("deltaRevocationList");
        LDAP_BINARY_OPTION_ATTRS.add("certificateRevocationList");
        LDAP_BINARY_OPTION_ATTRS.add("crossCertificatePair");
        LDAP_BINARY_OPTION_ATTRS.add("supportedAlgorithms");
    }

    protected static final String LDAP_CTX_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";

    private static final Log LOG = Log.getLog(LdapConnection.class);

    protected final LdapConfiguration config;

    protected LdapSchema schema;

    protected LdapContext initCtx;

    protected StartTlsResponse tlsCtx;

    protected Set<String> supportedControls;

    protected ServerType serverType;

    public LdapConnection(LdapConfiguration config) {
        this.config = config;
        schema = new LdapSchema(this);
    }

    public String format(String key, String dflt, Object... args) {
        return config.getConnectorMessages().format(key, dflt, args);
    }

    public LdapConfiguration getConfiguration() {
        return config;
    }

    public LdapContext getInitialContext() {
        if (initCtx != null) {
            return initCtx;
        }
        Pair<LdapContext, StartTlsResponse> connectPair = connect(config.getPrincipal(), config.getCredentials());
        initCtx = connectPair.first;
        tlsCtx = connectPair.second;
        return initCtx;
    }

    protected Pair<LdapContext, StartTlsResponse> connect(String principal, GuardedString credentials) {
        Pair<AuthenticationResult, Pair<LdapContext, StartTlsResponse>> pair = createContext(principal, credentials);
        if (pair.first.getType().equals(AuthenticationResultType.SUCCESS)) {
            return pair.second;
        }
        pair.first.propagate();
        throw new IllegalStateException("Should never get here");
    }

    protected Pair<AuthenticationResult, Pair<LdapContext, StartTlsResponse>> createContext(String principal, GuardedString credentials) {
        final List<Pair<AuthenticationResult, Pair<LdapContext, StartTlsResponse>>> result =
                new ArrayList<Pair<AuthenticationResult, Pair<LdapContext, StartTlsResponse>>>(1);

        final Hashtable<Object, Object> env = new Hashtable<Object, Object>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, LDAP_CTX_FACTORY);
        env.put(Context.PROVIDER_URL, getLdapUrls());
        env.put(Context.REFERRAL, "follow");
        env.put(LdapConstants.CONNECT_TIMEOUT_ENV_PROP, Long.toString(config.getConnectTimeout()));
        env.put(LdapConstants.READ_TIMEOUT_ENV_PROP, Long.toString(config.getReadTimeout()));

        if (config.isSsl()) {
            env.put(Context.SECURITY_PROTOCOL, "ssl");
        }

        String authentication = StringUtil.isNotBlank(principal) ? "simple" : "none";
        env.put(Context.SECURITY_AUTHENTICATION, authentication);

        if (StringUtil.isNotBlank(principal)) {
            env.put(Context.SECURITY_PRINCIPAL, principal);
            if (credentials != null) {
                credentials.access(new Accessor() {

                    @Override
                    public void access(final char[] clearChars) {
                        if(clearChars == null || clearChars.length == 0){
                            throw new InvalidCredentialException("Password is blank");
                        }
                        env.put(Context.SECURITY_CREDENTIALS, clearChars);
                        // Connect while in the accessor, otherwise clearChars will be cleared.
                        result.add(createContext(env));
                    }
                });
                assert !result.isEmpty();
            } else {
                result.add(createContext(env));
            }
        } else {
            result.add(createContext(env));
        }

        return result.get(0);
    }

    protected Pair<AuthenticationResult, Pair<LdapContext, StartTlsResponse>> createContext(final Hashtable<?, ?> env) {
        AuthenticationResult authnResult = null;
        InitialLdapContext context = null;
        StartTlsResponse tlsContext = null;
        try {
            context = new InitialLdapContext(env, null);
            // if needed, start TLS connection
            if (config.isStartTLSEnabled()) {
                tlsContext = (StartTlsResponse) context.extendedOperation(new StartTlsRequest());
                tlsContext.negotiate();
                // must re-bind after tls negotiation
                context.reconnect(null);
            }
            
            if (config.isRespectResourcePasswordPolicyChangeAfterReset()) {
                if (hasPasswordExpiredControl(context.getResponseControls())) {
                    authnResult = new AuthenticationResult(
                            AuthenticationResultType.PASSWORD_EXPIRED);
                }
            }
            // TODO: process Password Policy control.
        } catch (AuthenticationException e) {
            String message = e.getMessage().toLowerCase();
            if (message.contains("password expired")) { // Sun DS.
                authnResult = new AuthenticationResult(AuthenticationResultType.PASSWORD_EXPIRED, e);
            } else if (message.contains("password has expired")) { // RACF.
                authnResult = new AuthenticationResult(AuthenticationResultType.PASSWORD_EXPIRED, e);
            } else {
                authnResult = new AuthenticationResult(AuthenticationResultType.FAILED, e);
            }
        } catch (NamingException e) {
            authnResult = new AuthenticationResult(AuthenticationResultType.FAILED, e);
        } catch (IOException e) {
            LOG.error("Unable to start TLS connection", e);
            authnResult = new AuthenticationResult(AuthenticationResultType.FAILED, e);
        }
        if (authnResult == null) {
            assert context != null;
            authnResult = new AuthenticationResult(AuthenticationResultType.SUCCESS);
        }
        return new Pair<AuthenticationResult, Pair<LdapContext, StartTlsResponse>>(authnResult,
                new Pair<LdapContext, StartTlsResponse>(context, tlsContext));
    }

    protected static boolean hasPasswordExpiredControl(Control[] controls) {
        if (controls != null) {
            for (Control control : controls) {
                if (control instanceof PasswordExpiredResponseControl) {
                    return true;
                }
            }
        }
        return false;
    }

    protected String getLdapUrls() {
        StringBuilder builder = new StringBuilder();
        builder.append("ldap://");
        builder.append(config.getHost());
        builder.append(':');
        builder.append(config.getPort());
        for (String failover : LdapUtil.nullAsEmpty(config.getFailover())) {
            builder.append(' ');
            builder.append(failover);
        }
        return builder.toString();
    }

    public void close() {
        try {
            quietClose(new Pair<LdapContext, StartTlsResponse>(initCtx, tlsCtx));
        } finally {
            initCtx = null;
        }
    }

    protected static void quietClose(Pair<LdapContext, StartTlsResponse> ctxPair) {
        try {
            if (ctxPair != null) {
                // first close TLS connection, if any
                if (ctxPair.second != null) {
                    ctxPair.second.close();
                }
                // then close context
                if (ctxPair.first != null) {
                    ctxPair.first.close();
                }
            }
        } catch (NamingException e) {
            LOG.warn(e, null);
        } catch (IOException e) {
            LOG.warn(e, null);
        }
    }

    public LdapSchema getSchema() {
        return schema;
    }

    public LdapNativeSchema createNativeSchema() {
        try {
            if (config.isReadSchema()) {
                return new ServerNativeSchema(this);
            } else {
                return new StaticNativeSchema();
            }
        } catch (NamingException e) {
            throw new ConnectorException(e);
        }
    }

    public AuthenticationResult authenticate(String entryDN, GuardedString password) {
        assert entryDN != null;
        LOG.ok("Attempting to authenticate {0}", entryDN);
        Pair<AuthenticationResult, Pair<LdapContext, StartTlsResponse>> pair = createContext(entryDN, password);
        if (pair.second != null) {
            quietClose(pair.second);
        }
        LOG.ok("Authentication result: {0}", pair.first);
        return pair.first;
    }

    public void test() {
        checkAlive();
    }

    public void checkAlive() {
        try {
            Attributes attrs = getInitialContext().getAttributes("", new String[] { "subschemaSubentry" });
            attrs.get("subschemaSubentry");
        } catch (NamingException e) {
            throw new ConnectorException(e);
        }
    }

    /**
     * Returns {@code} true if the control with the given OID is supported by the server.
     */
    public boolean supportsControl(final String oid) {
        return getSupportedControls().contains(oid);
    }

    protected Set<String> getSupportedControls() {
        if (supportedControls == null) {
            try {
                Attributes attrs = getInitialContext().getAttributes("", new String[] { "supportedControl" });
                supportedControls =
                        Collections.unmodifiableSet(LdapUtil.getStringAttrValues(attrs, "supportedControl"));
            } catch (NamingException e) {
                LOG.warn(e, "Exception while retrieving the supported controls");
                supportedControls = Collections.emptySet();
            }
        }
        return supportedControls;
    }

    public ServerType getServerType() {
        if (serverType == null) {
            serverType = detectServerType();
        }
        return serverType;
    }

    protected ServerType detectServerType() {
        try {
            Attributes attrs = getInitialContext().getAttributes("", new String[] { "vendorVersion" });
            String vendorVersion = LdapUtil.getStringAttrValue(attrs, "vendorVersion");
            if (vendorVersion != null) {
                vendorVersion = vendorVersion.toLowerCase();
                if (vendorVersion.contains("opendj")) {
                    return ServerType.OPENDJ;
                }
                if (vendorVersion.contains("sun") && vendorVersion.contains("directory")) {
                    return ServerType.SUN_DSEE;
                }
            }
        } catch (NamingException e) {
            LOG.warn(e, "Exception while detecting the server type");
        }
        return ServerType.UNKNOWN;
    }

    public boolean needsBinaryOption(String attrName) {
        return LDAP_BINARY_OPTION_ATTRS.contains(attrName);
    }

    public boolean isBinarySyntax(String attrName) {
        return LDAP_BINARY_SYNTAX_ATTRS.contains(attrName);
    }

    public enum AuthenticationResultType {

        SUCCESS {

                    @Override
                    public void propagate(Exception cause) {
                    }
                },
        PASSWORD_EXPIRED {

                    @Override
                    public void propagate(Exception cause) {
                        throw new PasswordExpiredException(cause);
                    }
                },
        FAILED {

                    @Override
                    public void propagate(Exception cause) {
                        throw new ConnectorSecurityException(cause);
                    }
                };

        public abstract void propagate(Exception cause);
    }

    public static class AuthenticationResult {

        protected final AuthenticationResultType type;

        protected final Exception cause;

        public AuthenticationResult(AuthenticationResultType type) {
            this(type, null);
        }

        public AuthenticationResult(AuthenticationResultType type, Exception cause) {
            assert type != null;
            this.type = type;
            this.cause = cause;
        }

        public void propagate() {
            type.propagate(cause);
        }

        public AuthenticationResultType getType() {
            return type;
        }

        @Override
        public String toString() {
            StringBuilder result = new StringBuilder();
            result.append("AuthenticationResult[type: ").append(type);
            if (cause != null) {
                result.append("; cause: ").append(cause.getMessage());
            }
            result.append(']');
            return result.toString();
        }
    }

    public enum ServerType {

        SUN_DSEE,
        OPENDJ,
        UNKNOWN

    }
}
