package com.github.bcanvural.security;

import java.io.Serializable;

import org.hippoecm.frontend.model.UserCredentials;

/**
 * SSO User State object which contains a pair of JSESSIONID and <code>UserCredentials</code>.
 */
class SSOUserState implements Serializable {

    private static final long serialVersionUID = 1L;

    static final String SAML_ID = SSOUserState.class.getName() + ".saml.id";

    private final UserCredentials credentials;
    private final String sessionId;

    SSOUserState(final UserCredentials credentials, final String sessionId) {
        this.credentials = credentials;
        this.sessionId = sessionId;
    }

    UserCredentials getCredentials() {
        return credentials;
    }

    String getSessionId() {
        return sessionId;
    }

}