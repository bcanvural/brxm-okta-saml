package com.github.bcanvural.security;

import org.hippoecm.frontend.model.UserCredentials;
import org.opensaml.saml2.core.NameID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLCredential;

import javax.jcr.SimpleCredentials;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class LoginSuccessFilter implements Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger( LoginSuccessFilter.class );

    private static final String SSO_USER_STATE = SSOUserState.class.getName();

    private static ThreadLocal<SSOUserState> tlCurrentSSOUserState = new ThreadLocal<SSOUserState>();

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        LOGGER.info("doFilter LoginSuccessFilter");

        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (!authentication.isAuthenticated()){
            LOGGER.debug("User not authenticated");
            chain.doFilter(request, response);
            return;
        }

        // Check if the user already has a SSO user state stored in HttpSession before.
        HttpSession session = ((HttpServletRequest) request).getSession();

        SSOUserState userState = (SSOUserState) session.getAttribute(SSO_USER_STATE);

        if(userState == null || !userState.getSessionId().equals(session.getId())) {
            if (authentication.getCredentials() instanceof SAMLCredential){
                SAMLCredential samlCredential = (SAMLCredential) authentication.getCredentials();
                final NameID nameID = samlCredential.getNameID();
                if (nameID == null){
                    LOGGER.warn("nameID is null in SAML Credentials");
                    chain.doFilter(request, response);
                    return;
                }
                final String username = nameID.getValue();
                SimpleCredentials creds = new SimpleCredentials(username, "DUMMY".toCharArray());
                creds.setAttribute(SSOUserState.SAML_ID, username);
                userState = new SSOUserState(new UserCredentials(creds), session.getId());
                session.setAttribute(SSO_USER_STATE, userState);



            } else {
                LOGGER.debug("Authenticated user credentials are not SAML credentials.");
                chain.doFilter(request, response);
                return;
            }

        }

        // If the user has a valid SSO user state, then
        // set a JCR Credentials as request attribute (named by FQCN of UserCredentials class).
        // Then the CMS application will use the JCR credentials passed through this request attribute.
        if (userState.getSessionId().equals(session.getId())) {
            request.setAttribute(UserCredentials.class.getName(), userState.getCredentials());
        }

        try {
            tlCurrentSSOUserState.set(userState);
            chain.doFilter(request, response);
        } finally {
            tlCurrentSSOUserState.remove();
        }

    }

    /**
     * Get current <code>SSOUserState</code> instance from the current thread local context.
     * @return
     */
    static SSOUserState getCurrentSSOUserState() {
        return tlCurrentSSOUserState.get();
    }

    @Override
    public void destroy() {

    }
}
