package de.tmobile.bsp.security.spring;


import java.util.Collection;
import java.util.HashSet;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class BspUsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Authentication result = null;
        if (authentication instanceof BspUsernamePasswordAuthenticationToken) {
            BspUsernamePasswordAuthenticationToken request = (BspUsernamePasswordAuthenticationToken) authentication;
            String username = request.getName();
            String password = request.getCredentials().toString();
            if (username.equals("u") && password.equals("p")) {
                Collection<SimpleGrantedAuthority> authorities = new HashSet<>();
                authorities.add(new SimpleGrantedAuthority("USER"));
                result = new BspUsernamePasswordAuthenticationToken(username, authorities);
            } else {
                throw new UsernameNotFoundException("user not found");
            }
        }
        return result;
    }

    @Override
    public boolean supports(Class<?> authClass) {
        return BspUsernamePasswordAuthenticationToken.class.isAssignableFrom(authClass);
    }
}
