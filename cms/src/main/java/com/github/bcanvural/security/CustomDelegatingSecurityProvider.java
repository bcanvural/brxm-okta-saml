package com.github.bcanvural.security;

import org.apache.commons.lang.*;
import org.apache.jackrabbit.api.security.user.*;
import org.apache.jackrabbit.value.*;
import org.hippoecm.repository.security.*;
import org.hippoecm.repository.security.user.*;
import org.slf4j.*;

import java.util.*;
import javax.jcr.*;

/**
 * Custom <code>org.hippoecm.repository.security.SecurityProvider</code> implementation.
 * <p>
 * Hippo Repository allows to set a custom security provider for various reasons (e.g, SSO) for specific users.
 * If a user is associated with a custom security provider, then Hippo Repository invokes
 * the custom security provider to do authentication and authorization.
 * </P>
 */
public class CustomDelegatingSecurityProvider extends DelegatingSecurityProvider {

    private static Logger log = LoggerFactory.getLogger(CustomDelegatingSecurityProvider.class);

    private HippoUserManager userManager;

    /**
     * Constructs by creating the default <code>RepositorySecurityProvider</code> to delegate all the other calls
     * except of authentication calls.
     *
     * @throws RepositoryException
     */
    public CustomDelegatingSecurityProvider() throws RepositoryException {
        super(new RepositorySecurityProvider());
    }

    /**
     * Returns a custom (delegating) HippoUserManager to authenticate a user by SAML Assertion.
     */
    @Override
    public UserManager getUserManager() throws RepositoryException {
        if (userManager == null) {
            userManager = new DelegatingHippoUserManager((HippoUserManager) super.getUserManager()) {
                @Override
                public boolean authenticate(SimpleCredentials creds) throws RepositoryException {
                    if (validateAuthentication(creds)) {
                        String userId = creds.getUserID();
                        if (!hasUser(userId)) {
                            //user doesn't exist in the repositoru
                            syncUser(createUser(userId), getGroupManager().getGroup("admin"));
                        }
                        return true;
                    } else {
                        return false;
                    }
                }
            };
        }
        return userManager;
    }

    /**
     * Returns a custom (delegating) HippoUserManager to authenticate a user by SAML Assertion.
     */
    @Override
    public UserManager getUserManager(Session session) throws RepositoryException {
        return new DelegatingHippoUserManager((HippoUserManager) super.getUserManager(session)) {
            @Override
            public boolean authenticate(SimpleCredentials creds) throws RepositoryException {
                if(validateAuthentication(creds)) {
                    String userId = creds.getUserID();
                    if (!hasUser(userId)) {
                        //user doesn't exist in the repositoru
                        syncUser(createUser(userId), getGroupManager().getGroup("admin"));
                    }
                    return true;
                } else{
                    return false;
                }
            }
        };
    }

    /**
     * Validates SAML SSO Assertion.
     * <p>
     * In this example, simply invokes SAML API (<code>AssertionHolder#getAssertion()</code>) to validate.
     * </P>
     *
     * @param creds
     * @return
     * @throws RepositoryException
     */
    protected boolean validateAuthentication(SimpleCredentials creds) throws RepositoryException {
        log.info("CustomDelegatingSecurityProvider validating credentials: {}", creds);

        SSOUserState userState = LoginSuccessFilter.getCurrentSSOUserState();

        /*
         * If userState found in the current thread context, this authentication request came from
         * CMS application.
         * Otherwise, this authentication request came from SITE application (e.g, channel manager rest service).
         */

            if (userState != null) {

            // Asserting must have been done by the *AssertionValidationFilter* and the assertion thread local variable
            // must have been set by AssertionThreadLocalFilter already.
            // So, simply check if you have assertion object in the thread local.
            return StringUtils.isNotEmpty(userState.getCredentials().getUsername());

        } else {

            String samlId = (String) creds.getAttribute(SSOUserState.SAML_ID);

            if (StringUtils.isNotBlank(samlId)) {
                log.info("Authentication allowed to: {}", samlId);
                return true;
            }
        }

        return false;
    }

    protected void syncUser(final Node user, final Node group) throws RepositoryException {
        user.setProperty("hipposys:securityprovider", "saml");
        user.setProperty("hipposys:active", true);
        //updating group members
        Value[] values = group.getProperties("hipposys:members").nextProperty().getValues();
        Value[] newValues = Arrays.copyOf(values, values.length + 1);
        newValues[values.length] = new StringValue(user.getName());
        group.setProperty("hipposys:members", newValues);
    }

}