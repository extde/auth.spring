package de.tmobile.bsp.security.spring;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.BspHttpSecurity;
import org.springframework.security.config.annotation.web.configuration.BspWebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@EnableWebSecurity
@ComponentScan("de.tmobile.bsp.security.spring")
public class WebSecurityConfig extends BspWebSecurityConfigurerAdapter {

    @Autowired
    private BspUsernamePasswordAuthenticationProvider bspAuthProvider;

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        return  new InMemoryUserDetailsManager(user);
    }

    @Override
    protected void configure(BspHttpSecurity http) throws Exception {

        // permit JSF resources unauthenticated
        // anything else require authenticated user
        http
                .authorizeRequests()
                .antMatchers("/javax.faces.resource/**").permitAll()
                .antMatchers("/index.html").permitAll()
                .anyRequest().authenticated();

        // form login
        http
                .formLogin()
                .loginPage("/login.xhtml")
                .usernameParameter("u")
                .passwordParameter("p")
                .failureUrl("/login.xhtml?error=true")
                .permitAll()
                .defaultSuccessUrl("/home.xhtml", true);
        // logout
        http.logout().logoutSuccessUrl("/login.xhtml");
        // not needed as JSF 2.2 is implicitly protected against CSRF
        http.csrf().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // add bsp authentication provider
        auth.authenticationProvider(bspAuthProvider);
    }
}
