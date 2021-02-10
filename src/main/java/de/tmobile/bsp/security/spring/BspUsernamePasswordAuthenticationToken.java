package de.tmobile.bsp.security.spring;

import java.util.Collection;
import java.util.HashSet;

import javax.security.auth.Subject;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class BspUsernamePasswordAuthenticationToken  extends AbstractAuthenticationToken {

    private String user;
    private String password;

    public BspUsernamePasswordAuthenticationToken(Object principal, Object credentials) {
        super(new HashSet<>());
        user = principal.toString();
        password = credentials.toString();
    }

    public BspUsernamePasswordAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        user = principal.toString();
        setAuthenticated(true);
    }
    @Override
    public Object getCredentials() {
        return password;
    }

    @Override
    public Object getPrincipal() {
        return user;
    }

    @Override
    public boolean implies(Subject subject) {
        return false;
    }
}
