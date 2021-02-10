package org.springframework.security.config.annotation.web.builders;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.config.annotation.web.configurers.ChannelSecurityConfigurer;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.annotation.web.configurers.JeeConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.PortMapperConfigurer;
import org.springframework.security.config.annotation.web.configurers.RememberMeConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.config.annotation.web.configurers.ServletApiConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.annotation.web.configurers.X509Configurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.filter.CorsFilter;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.config.annotation.web.configurers.BspFormLoginConfigurer;

public class BspHttpSecurity  extends
        AbstractConfiguredSecurityBuilder<DefaultSecurityFilterChain, BspHttpSecurity>
        implements SecurityBuilder<DefaultSecurityFilterChain>,
        HttpSecurityBuilder<BspHttpSecurity> {

    private final BspHttpSecurity.RequestMatcherConfigurer requestMatcherConfigurer;
    private List<Filter> filters = new ArrayList<>();
    private RequestMatcher requestMatcher = AnyRequestMatcher.INSTANCE;
    private BspFilterComparator comparator = new BspFilterComparator();

    /**
     * Creates a new instance
     * @param objectPostProcessor the {@link ObjectPostProcessor} that should be used
     * @param authenticationBuilder the {@link AuthenticationManagerBuilder} to use for
     * additional updates
     * @param sharedObjects the shared Objects to initialize the {@link BspHttpSecurity} with
     * @see WebSecurityConfiguration
     */
    @SuppressWarnings("unchecked")
    public BspHttpSecurity(ObjectPostProcessor<Object> objectPostProcessor,
                        AuthenticationManagerBuilder authenticationBuilder,
                        Map<Class<?>, Object> sharedObjects) {
        super(objectPostProcessor);
        Assert.notNull(authenticationBuilder, "authenticationBuilder cannot be null");
        setSharedObject(AuthenticationManagerBuilder.class, authenticationBuilder);
        for (Map.Entry<Class<?>, Object> entry : sharedObjects
                .entrySet()) {
            setSharedObject((Class<Object>) entry.getKey(), entry.getValue());
        }
        ApplicationContext context = (ApplicationContext) sharedObjects
                .get(ApplicationContext.class);
        this.requestMatcherConfigurer = new BspHttpSecurity.RequestMatcherConfigurer(context);
    }

    private ApplicationContext getContext() {
        return getSharedObject(ApplicationContext.class);
    }

    /**
     * Adds the Security headers to the response. This is activated by default when using
     * {@link WebSecurityConfigurerAdapter}'s default constructor. Accepting the
     * default provided by {@link WebSecurityConfigurerAdapter} or only invoking
     * {@link #headers()} without invoking additional methods on it, is the equivalent of:
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     *     protected void configure(BspHttpSecurity http) throws Exception {
     *         http
     *             .headers()
     *                 .contentTypeOptions()
     *                 .and()
     *                 .xssProtection()
     *                 .and()
     *                 .cacheControl()
     *                 .and()
     *                 .httpStrictTransportSecurity()
     *                 .and()
     *                 .frameOptions()
     *                 .and()
     *             ...;
     *     }
     * }
     * </pre>
     *
     * You can disable the headers using the following:
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     *     protected void configure(BspHttpSecurity http) throws Exception {
     *         http
     *             .headers().disable()
     *             ...;
     *     }
     * }
     * </pre>
     *
     * You can enable only a few of the headers by first invoking
     * {@link HeadersConfigurer#defaultsDisabled()}
     * and then invoking the appropriate methods on the {@link #headers()} result.
     * For example, the following will enable {@link HeadersConfigurer#cacheControl()} and
     * {@link HeadersConfigurer#frameOptions()} only.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     *     protected void configure(BspHttpSecurity http) throws Exception {
     *         http
     *             .headers()
     *                  .defaultsDisabled()
     *                  .cacheControl()
     *                  .and()
     *                  .frameOptions()
     *                  .and()
     *             ...;
     *     }
     * }
     * </pre>
     *
     * You can also choose to keep the defaults but explicitly disable a subset of headers.
     * For example, the following will enable all the default headers except
     * {@link HeadersConfigurer#frameOptions()}.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     *     protected void configure(BspHttpSecurity http) throws Exception {
     *         http
     *             .headers()
     *                  .frameOptions()
     *                  	.disable()
     *                  .and()
     *             ...;
     *     }
     * }
     * </pre>
     *
     * @return the {@link HeadersConfigurer} for further customizations
     * @throws Exception
     * @see HeadersConfigurer
     */
    public HeadersConfigurer<BspHttpSecurity> headers() throws Exception {
        return getOrApply(new HeadersConfigurer<>());
    }

    /**
     * Adds the Security headers to the response. This is activated by default when using
     * {@link WebSecurityConfigurerAdapter}'s default constructor.
     *
     * <h2>Example Configurations</h2>
     *
     * Accepting the default provided by {@link WebSecurityConfigurerAdapter} or only invoking
     * {@link #headers()} without invoking additional methods on it, is the equivalent of:
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *	&#064;Override
     *	protected void configure(BspHttpSecurity http) throws Exception {
     *		http
     *			.headers(headers ->
     *				headers
     *					.contentTypeOptions(withDefaults())
     *					.xssProtection(withDefaults())
     *					.cacheControl(withDefaults())
     *					.httpStrictTransportSecurity(withDefaults())
     *					.frameOptions(withDefaults()
     *			);
     *	}
     * }
     * </pre>
     *
     * You can disable the headers using the following:
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *	&#064;Override
     *	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.headers(headers -> headers.disable());
     *	}
     * }
     * </pre>
     *
     * You can enable only a few of the headers by first invoking
     * {@link HeadersConfigurer#defaultsDisabled()}
     * and then invoking the appropriate methods on the {@link #headers()} result.
     * For example, the following will enable {@link HeadersConfigurer#cacheControl()} and
     * {@link HeadersConfigurer#frameOptions()} only.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *	&#064;Override
     *	protected void configure(BspHttpSecurity http) throws Exception {
     *		http
     *			.headers(headers ->
     *				headers
     *			 		.defaultsDisabled()
     *			 		.cacheControl(withDefaults())
     *			 		.frameOptions(withDefaults())
     *			);
     * 	}
     * }
     * </pre>
     *
     * You can also choose to keep the defaults but explicitly disable a subset of headers.
     * For example, the following will enable all the default headers except
     * {@link HeadersConfigurer#frameOptions()}.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     *  protected void configure(BspHttpSecurity http) throws Exception {
     *  	http
     *  		.headers(headers ->
     *  			headers
     *  				.frameOptions(frameOptions -> frameOptions.disable())
     *  		);
     * }
     * </pre>
     *
     * @param headersCustomizer the {@link Customizer} to provide more options for
     * the {@link HeadersConfigurer}
     * @return the {@link BspHttpSecurity} for further customizations
     * @throws Exception
     */
    public BspHttpSecurity headers(Customizer<HeadersConfigurer<BspHttpSecurity>> headersCustomizer) throws Exception {
        headersCustomizer.customize(getOrApply(new HeadersConfigurer<>()));
        return BspHttpSecurity.this;
    }

    /**
     * Adds a {@link CorsFilter} to be used. If a bean by the name of corsFilter is
     * provided, that {@link CorsFilter} is used. Else if corsConfigurationSource is
     * defined, then that {@link CorsConfiguration} is used. Otherwise, if Spring MVC is
     * on the classpath a {@link HandlerMappingIntrospector} is used.
     *
     * @return the {@link CorsConfigurer} for customizations
     * @throws Exception
     */
    public CorsConfigurer<BspHttpSecurity> cors() throws Exception {
        return getOrApply(new CorsConfigurer<>());
    }

    /**
     * Adds a {@link CorsFilter} to be used. If a bean by the name of corsFilter is
     * provided, that {@link CorsFilter} is used. Else if corsConfigurationSource is
     * defined, then that {@link CorsConfiguration} is used. Otherwise, if Spring MVC is
     * on the classpath a {@link HandlerMappingIntrospector} is used.
     * You can enable CORS using:
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class CorsSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     *     protected void configure(BspHttpSecurity http) throws Exception {
     *         http
     *             .cors(withDefaults());
     *     }
     * }
     * </pre>
     *
     * @param corsCustomizer the {@link Customizer} to provide more options for
     * the {@link CorsConfigurer}
     * @return the {@link BspHttpSecurity} for further customizations
     * @throws Exception
     */
    public BspHttpSecurity cors(Customizer<CorsConfigurer<BspHttpSecurity>> corsCustomizer) throws Exception {
        corsCustomizer.customize(getOrApply(new CorsConfigurer<>()));
        return BspHttpSecurity.this;
    }

    /**
     * Allows configuring of Session Management.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration demonstrates how to enforce that only a single instance
     * of a user is authenticated at a time. If a user authenticates with the username
     * "user" without logging out and an attempt to authenticate with "user" is made the
     * first session will be forcibly terminated and sent to the "/login?expired" URL.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class SessionManagementSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http.authorizeRequests().anyRequest().hasRole(&quot;USER&quot;).and().formLogin()
     * 				.permitAll().and().sessionManagement().maximumSessions(1)
     * 				.expiredUrl(&quot;/login?expired&quot;);
     * 	}
     *
     * 	&#064;Override
     * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
     * 	}
     * }
     * </pre>
     *
     * When using {@link SessionManagementConfigurer#maximumSessions(int)}, do not forget
     * to configure {@link HttpSessionEventPublisher} for the application to ensure that
     * expired sessions are cleaned up.
     *
     * In a web.xml this can be configured using the following:
     *
     * <pre>
     * &lt;listener&gt;
     *      &lt;listener-class&gt;org.springframework.security.web.session.HttpSessionEventPublisher&lt;/listener-class&gt;
     * &lt;/listener&gt;
     * </pre>
     *
     * Alternatively,
     * {@link AbstractSecurityWebApplicationInitializer#enableHttpSessionEventPublisher()}
     * could return true.
     *
     * @return the {@link SessionManagementConfigurer} for further customizations
     * @throws Exception
     */
    public SessionManagementConfigurer<BspHttpSecurity> sessionManagement() throws Exception {
        return getOrApply(new SessionManagementConfigurer<>());
    }

    /**
     * Allows configuring of Session Management.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration demonstrates how to enforce that only a single instance
     * of a user is authenticated at a time. If a user authenticates with the username
     * "user" without logging out and an attempt to authenticate with "user" is made the
     * first session will be forcibly terminated and sent to the "/login?expired" URL.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class SessionManagementSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.authorizeRequests(authorizeRequests ->
     * 				authorizeRequests
     * 					.anyRequest().hasRole(&quot;USER&quot;)
     * 			)
     * 			.formLogin(formLogin ->
     * 				formLogin
     * 					.permitAll()
     * 			)
     * 			.sessionManagement(sessionManagement ->
     * 				sessionManagement
     * 					.sessionConcurrency(sessionConcurrency ->
     * 						sessionConcurrency
     * 							.maximumSessions(1)
     * 							.expiredUrl(&quot;/login?expired&quot;)
     * 					)
     * 			);
     * 	}
     * }
     * </pre>
     *
     * When using {@link SessionManagementConfigurer#maximumSessions(int)}, do not forget
     * to configure {@link HttpSessionEventPublisher} for the application to ensure that
     * expired sessions are cleaned up.
     *
     * In a web.xml this can be configured using the following:
     *
     * <pre>
     * &lt;listener&gt;
     *      &lt;listener-class&gt;org.springframework.security.web.session.HttpSessionEventPublisher&lt;/listener-class&gt;
     * &lt;/listener&gt;
     * </pre>
     *
     * Alternatively,
     * {@link AbstractSecurityWebApplicationInitializer#enableHttpSessionEventPublisher()}
     * could return true.
     *
     * @param sessionManagementCustomizer the {@link Customizer} to provide more options for
     * the {@link SessionManagementConfigurer}
     * @return the {@link BspHttpSecurity} for further customizations
     * @throws Exception
     */
    public BspHttpSecurity sessionManagement(Customizer<SessionManagementConfigurer<BspHttpSecurity>> sessionManagementCustomizer) throws Exception {
        sessionManagementCustomizer.customize(getOrApply(new SessionManagementConfigurer<>()));
        return BspHttpSecurity.this;
    }

    /**
     * Allows configuring a {@link PortMapper} that is available from
     * {@link BspHttpSecurity#getSharedObject(Class)}. Other provided
     * {@link SecurityConfigurer} objects use this configured {@link PortMapper} as a
     * default {@link PortMapper} when redirecting from HTTP to HTTPS or from HTTPS to
     * HTTP (for example when used in combination with {@link #requiresChannel()}. By
     * default Spring Security uses a {@link PortMapperImpl} which maps the HTTP port 8080
     * to the HTTPS port 8443 and the HTTP port of 80 to the HTTPS port of 443.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration will ensure that redirects within Spring Security from
     * HTTP of a port of 9090 will redirect to HTTPS port of 9443 and the HTTP port of 80
     * to the HTTPS port of 443.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class PortMapperSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
     * 				.permitAll().and()
     * 				// Example portMapper() configuration
     * 				.portMapper().http(9090).mapsTo(9443).http(80).mapsTo(443);
     * 	}
     *
     * 	&#064;Override
     * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
     * 	}
     * }
     * </pre>
     *
     * @return the {@link PortMapperConfigurer} for further customizations
     * @throws Exception
     * @see #requiresChannel()
     */
    public PortMapperConfigurer<BspHttpSecurity> portMapper() throws Exception {
        return getOrApply(new PortMapperConfigurer<>());
    }

    /**
     * Allows configuring a {@link PortMapper} that is available from
     * {@link BspHttpSecurity#getSharedObject(Class)}. Other provided
     * {@link SecurityConfigurer} objects use this configured {@link PortMapper} as a
     * default {@link PortMapper} when redirecting from HTTP to HTTPS or from HTTPS to
     * HTTP (for example when used in combination with {@link #requiresChannel()}. By
     * default Spring Security uses a {@link PortMapperImpl} which maps the HTTP port 8080
     * to the HTTPS port 8443 and the HTTP port of 80 to the HTTPS port of 443.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration will ensure that redirects within Spring Security from
     * HTTP of a port of 9090 will redirect to HTTPS port of 9443 and the HTTP port of 80
     * to the HTTPS port of 443.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class PortMapperSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.requiresChannel(requiresChannel ->
     * 				requiresChannel
     * 					.anyRequest().requiresSecure()
     * 			)
     * 			.portMapper(portMapper ->
     * 				portMapper
     * 					.http(9090).mapsTo(9443)
     * 					.http(80).mapsTo(443)
     * 			);
     * 	}
     * }
     * </pre>
     *
     * @see #requiresChannel()
     * @param portMapperCustomizer the {@link Customizer} to provide more options for
     * the {@link PortMapperConfigurer}
     * @return the {@link BspHttpSecurity} for further customizations
     * @throws Exception
     */
    public BspHttpSecurity portMapper(Customizer<PortMapperConfigurer<BspHttpSecurity>> portMapperCustomizer) throws Exception {
        portMapperCustomizer.customize(getOrApply(new PortMapperConfigurer<>()));
        return BspHttpSecurity.this;
    }

    /**
     * Configures container based pre authentication. In this case, authentication
     * is managed by the Servlet Container.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration will use the principal found on the
     * {@link HttpServletRequest} and if the user is in the role "ROLE_USER" or
     * "ROLE_ADMIN" will add that to the resulting {@link Authentication}.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class JeeSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and()
     * 		// Example jee() configuration
     * 				.jee().mappableRoles(&quot;USER&quot;, &quot;ADMIN&quot;);
     * 	}
     * }
     * </pre>
     *
     * Developers wishing to use pre authentication with the container will need to ensure
     * their web.xml configures the security constraints. For example, the web.xml (there
     * is no equivalent Java based configuration supported by the Servlet specification)
     * might look like:
     *
     * <pre>
     * &lt;login-config&gt;
     *     &lt;auth-method&gt;FORM&lt;/auth-method&gt;
     *     &lt;form-login-config&gt;
     *         &lt;form-login-page&gt;/login&lt;/form-login-page&gt;
     *         &lt;form-error-page&gt;/login?error&lt;/form-error-page&gt;
     *     &lt;/form-login-config&gt;
     * &lt;/login-config&gt;
     *
     * &lt;security-role&gt;
     *     &lt;role-name&gt;ROLE_USER&lt;/role-name&gt;
     * &lt;/security-role&gt;
     * &lt;security-constraint&gt;
     *     &lt;web-resource-collection&gt;
     *     &lt;web-resource-name&gt;Public&lt;/web-resource-name&gt;
     *         &lt;description&gt;Matches unconstrained pages&lt;/description&gt;
     *         &lt;url-pattern&gt;/login&lt;/url-pattern&gt;
     *         &lt;url-pattern&gt;/logout&lt;/url-pattern&gt;
     *         &lt;url-pattern&gt;/resources/*&lt;/url-pattern&gt;
     *     &lt;/web-resource-collection&gt;
     * &lt;/security-constraint&gt;
     * &lt;security-constraint&gt;
     *     &lt;web-resource-collection&gt;
     *         &lt;web-resource-name&gt;Secured Areas&lt;/web-resource-name&gt;
     *         &lt;url-pattern&gt;/*&lt;/url-pattern&gt;
     *     &lt;/web-resource-collection&gt;
     *     &lt;auth-constraint&gt;
     *         &lt;role-name&gt;ROLE_USER&lt;/role-name&gt;
     *     &lt;/auth-constraint&gt;
     * &lt;/security-constraint&gt;
     * </pre>
     *
     * Last you will need to configure your container to contain the user with the correct
     * roles. This configuration is specific to the Servlet Container, so consult your
     * Servlet Container's documentation.
     *
     * @return the {@link JeeConfigurer} for further customizations
     * @throws Exception
     */
    public JeeConfigurer<BspHttpSecurity> jee() throws Exception {
        return getOrApply(new JeeConfigurer<>());
    }

    /**
     * Configures container based pre authentication. In this case, authentication
     * is managed by the Servlet Container.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration will use the principal found on the
     * {@link HttpServletRequest} and if the user is in the role "ROLE_USER" or
     * "ROLE_ADMIN" will add that to the resulting {@link Authentication}.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class JeeSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.authorizeRequests(authorizeRequests ->
     * 				authorizeRequests
     * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 			)
     * 			.jee(jee ->
     * 				jee
     * 					.mappableRoles(&quot;USER&quot;, &quot;ADMIN&quot;)
     * 			);
     * 	}
     * }
     * </pre>
     *
     * Developers wishing to use pre authentication with the container will need to ensure
     * their web.xml configures the security constraints. For example, the web.xml (there
     * is no equivalent Java based configuration supported by the Servlet specification)
     * might look like:
     *
     * <pre>
     * &lt;login-config&gt;
     *     &lt;auth-method&gt;FORM&lt;/auth-method&gt;
     *     &lt;form-login-config&gt;
     *         &lt;form-login-page&gt;/login&lt;/form-login-page&gt;
     *         &lt;form-error-page&gt;/login?error&lt;/form-error-page&gt;
     *     &lt;/form-login-config&gt;
     * &lt;/login-config&gt;
     *
     * &lt;security-role&gt;
     *     &lt;role-name&gt;ROLE_USER&lt;/role-name&gt;
     * &lt;/security-role&gt;
     * &lt;security-constraint&gt;
     *     &lt;web-resource-collection&gt;
     *     &lt;web-resource-name&gt;Public&lt;/web-resource-name&gt;
     *         &lt;description&gt;Matches unconstrained pages&lt;/description&gt;
     *         &lt;url-pattern&gt;/login&lt;/url-pattern&gt;
     *         &lt;url-pattern&gt;/logout&lt;/url-pattern&gt;
     *         &lt;url-pattern&gt;/resources/*&lt;/url-pattern&gt;
     *     &lt;/web-resource-collection&gt;
     * &lt;/security-constraint&gt;
     * &lt;security-constraint&gt;
     *     &lt;web-resource-collection&gt;
     *         &lt;web-resource-name&gt;Secured Areas&lt;/web-resource-name&gt;
     *         &lt;url-pattern&gt;/*&lt;/url-pattern&gt;
     *     &lt;/web-resource-collection&gt;
     *     &lt;auth-constraint&gt;
     *         &lt;role-name&gt;ROLE_USER&lt;/role-name&gt;
     *     &lt;/auth-constraint&gt;
     * &lt;/security-constraint&gt;
     * </pre>
     *
     * Last you will need to configure your container to contain the user with the correct
     * roles. This configuration is specific to the Servlet Container, so consult your
     * Servlet Container's documentation.
     *
     * @param jeeCustomizer the {@link Customizer} to provide more options for
     * the {@link JeeConfigurer}
     * @return the {@link BspHttpSecurity} for further customizations
     * @throws Exception
     */
    public BspHttpSecurity jee(Customizer<JeeConfigurer<BspHttpSecurity>> jeeCustomizer) throws Exception {
        jeeCustomizer.customize(getOrApply(new JeeConfigurer<>()));
        return BspHttpSecurity.this;
    }

    /**
     * Configures X509 based pre authentication.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration will attempt to extract the username from the X509
     * certificate. Remember that the Servlet Container will need to be configured to
     * request client certificates in order for this to work.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class X509SecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and()
     * 		// Example x509() configuration
     * 				.x509();
     * 	}
     * }
     * </pre>
     *
     * @return the {@link X509Configurer} for further customizations
     * @throws Exception
     */
    public X509Configurer<BspHttpSecurity> x509() throws Exception {
        return getOrApply(new X509Configurer<>());
    }

    /**
     * Configures X509 based pre authentication.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration will attempt to extract the username from the X509
     * certificate. Remember that the Servlet Container will need to be configured to
     * request client certificates in order for this to work.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class X509SecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.authorizeRequests(authorizeRequests ->
     * 				authorizeRequests
     * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 			)
     * 			.x509(withDefaults());
     * 	}
     * }
     * </pre>
     *
     * @param x509Customizer the {@link Customizer} to provide more options for
     * the {@link X509Configurer}
     * @return the {@link BspHttpSecurity} for further customizations
     * @throws Exception
     */
    public BspHttpSecurity x509(Customizer<X509Configurer<BspHttpSecurity>> x509Customizer) throws Exception {
        x509Customizer.customize(getOrApply(new X509Configurer<>()));
        return BspHttpSecurity.this;
    }

    /**
     * Allows configuring of Remember Me authentication.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration demonstrates how to allow token based remember me
     * authentication. Upon authenticating if the HTTP parameter named "remember-me"
     * exists, then the user will be remembered even after their
     * {@link javax.servlet.http.HttpSession} expires.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class RememberMeSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
     * 	}
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
     * 				.permitAll().and()
     * 				// Example Remember Me Configuration
     * 				.rememberMe();
     * 	}
     * }
     * </pre>
     *
     * @return the {@link RememberMeConfigurer} for further customizations
     * @throws Exception
     */
    public RememberMeConfigurer<BspHttpSecurity> rememberMe() throws Exception {
        return getOrApply(new RememberMeConfigurer<>());
    }

    /**
     * Allows configuring of Remember Me authentication.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration demonstrates how to allow token based remember me
     * authentication. Upon authenticating if the HTTP parameter named "remember-me"
     * exists, then the user will be remembered even after their
     * {@link javax.servlet.http.HttpSession} expires.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class RememberMeSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.authorizeRequests(authorizeRequests ->
     * 				authorizeRequests
     * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 			)
     * 			.formLogin(withDefaults())
     * 			.rememberMe(withDefaults());
     * 	}
     * }
     * </pre>
     *
     * @param rememberMeCustomizer the {@link Customizer} to provide more options for
     * the {@link RememberMeConfigurer}
     * @return the {@link BspHttpSecurity} for further customizations
     * @throws Exception
     */
    public BspHttpSecurity rememberMe(Customizer<RememberMeConfigurer<BspHttpSecurity>> rememberMeCustomizer) throws Exception {
        rememberMeCustomizer.customize(getOrApply(new RememberMeConfigurer<>()));
        return BspHttpSecurity.this;
    }

    /**
     * Allows restricting access based upon the {@link HttpServletRequest} using
     * {@link RequestMatcher} implementations (i.e. via URL patterns).
     *
     * <h2>Example Configurations</h2>
     *
     * The most basic example is to configure all URLs to require the role "ROLE_USER".
     * The configuration below requires authentication to every URL and will grant access
     * to both the user "admin" and "user".
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin();
     * 	}
     *
     * 	&#064;Override
     * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;)
     * 				.and().withUser(&quot;admin&quot;).password(&quot;password&quot;).roles(&quot;ADMIN&quot;, &quot;USER&quot;);
     * 	}
     * }
     * </pre>
     *
     * We can also configure multiple URLs. The configuration below requires
     * authentication to every URL and will grant access to URLs starting with /admin/ to
     * only the "admin" user. All other URLs either user can access.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http.authorizeRequests().antMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
     * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin();
     * 	}
     *
     * 	&#064;Override
     * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;)
     * 				.and().withUser(&quot;admin&quot;).password(&quot;password&quot;).roles(&quot;ADMIN&quot;, &quot;USER&quot;);
     * 	}
     * }
     * </pre>
     *
     * Note that the matchers are considered in order. Therefore, the following is invalid
     * because the first matcher matches every request and will never get to the second
     * mapping:
     *
     * <pre>
     * http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).antMatchers(&quot;/admin/**&quot;)
     * 		.hasRole(&quot;ADMIN&quot;)
     * </pre>
     *
     * @see #requestMatcher(RequestMatcher)
     *
     * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customizations
     * @throws Exception
     */
    public ExpressionUrlAuthorizationConfigurer<BspHttpSecurity>.ExpressionInterceptUrlRegistry authorizeRequests()
            throws Exception {
        ApplicationContext context = getContext();
        return getOrApply(new ExpressionUrlAuthorizationConfigurer<>(context))
                .getRegistry();
    }

    /**
     * Allows restricting access based upon the {@link HttpServletRequest} using
     * {@link RequestMatcher} implementations (i.e. via URL patterns).
     *
     * <h2>Example Configurations</h2>
     *
     * The most basic example is to configure all URLs to require the role "ROLE_USER".
     * The configuration below requires authentication to every URL and will grant access
     * to both the user "admin" and "user".
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.authorizeRequests(authorizeRequests ->
     * 				authorizeRequests
     * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 			)
     * 			.formLogin(withDefaults());
     * 	}
     * }
     * </pre>
     *
     * We can also configure multiple URLs. The configuration below requires
     * authentication to every URL and will grant access to URLs starting with /admin/ to
     * only the "admin" user. All other URLs either user can access.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.authorizeRequests(authorizeRequests ->
     * 				authorizeRequests
     * 					.antMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
     * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 			)
     * 			.formLogin(withDefaults());
     * 	}
     * }
     * </pre>
     *
     * Note that the matchers are considered in order. Therefore, the following is invalid
     * because the first matcher matches every request and will never get to the second
     * mapping:
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		 http
     * 		 	.authorizeRequests(authorizeRequests ->
     * 		 		authorizeRequests
     * 			 		.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 			 		.antMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
     * 		 	);
     * 	}
     * }
     * </pre>
     *
     * @see #requestMatcher(RequestMatcher)
     *
     * @param authorizeRequestsCustomizer the {@link Customizer} to provide more options for
     * the {@link ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry}
     * @return the {@link BspHttpSecurity} for further customizations
     * @throws Exception
     */
    public BspHttpSecurity authorizeRequests(Customizer<ExpressionUrlAuthorizationConfigurer<BspHttpSecurity>.ExpressionInterceptUrlRegistry> authorizeRequestsCustomizer)
            throws Exception {
        ApplicationContext context = getContext();
        authorizeRequestsCustomizer.customize(getOrApply(new ExpressionUrlAuthorizationConfigurer<>(context))
                .getRegistry());
        return BspHttpSecurity.this;
    }

    /**
     * Allows configuring the Request Cache. For example, a protected page (/protected)
     * may be requested prior to authentication. The application will redirect the user to
     * a login page. After authentication, Spring Security will redirect the user to the
     * originally requested protected page (/protected). This is automatically applied
     * when using {@link WebSecurityConfigurerAdapter}.
     *
     * @return the {@link RequestCacheConfigurer} for further customizations
     * @throws Exception
     */
    public RequestCacheConfigurer<BspHttpSecurity> requestCache() throws Exception {
        return getOrApply(new RequestCacheConfigurer<>());
    }

    /**
     * Allows configuring the Request Cache. For example, a protected page (/protected)
     * may be requested prior to authentication. The application will redirect the user to
     * a login page. After authentication, Spring Security will redirect the user to the
     * originally requested protected page (/protected). This is automatically applied
     * when using {@link WebSecurityConfigurerAdapter}.
     *
     * <h2>Example Custom Configuration</h2>
     *
     * The following example demonstrates how to disable request caching.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class RequestCacheDisabledSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.authorizeRequests(authorizeRequests ->
     * 				authorizeRequests
     * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 			)
     * 			.requestCache(requestCache ->
     * 				requestCache.disable()
     * 			);
     * 	}
     * }
     * </pre>
     *
     * @param requestCacheCustomizer the {@link Customizer} to provide more options for
     * the {@link RequestCacheConfigurer}
     * @return the {@link BspHttpSecurity} for further customizations
     * @throws Exception
     */
    public BspHttpSecurity requestCache(Customizer<RequestCacheConfigurer<BspHttpSecurity>> requestCacheCustomizer)
            throws Exception {
        requestCacheCustomizer.customize(getOrApply(new RequestCacheConfigurer<>()));
        return BspHttpSecurity.this;
    }

    /**
     * Allows configuring exception handling. This is automatically applied when using
     * {@link WebSecurityConfigurerAdapter}.
     *
     * @return the {@link ExceptionHandlingConfigurer} for further customizations
     * @throws Exception
     */
    public ExceptionHandlingConfigurer<BspHttpSecurity> exceptionHandling() throws Exception {
        return getOrApply(new ExceptionHandlingConfigurer<>());
    }

    /**
     * Allows configuring exception handling. This is automatically applied when using
     * {@link WebSecurityConfigurerAdapter}.
     *
     * <h2>Example Custom Configuration</h2>
     *
     * The following customization will ensure that users who are denied access are forwarded
     * to the page "/errors/access-denied".
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class ExceptionHandlingSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.authorizeRequests(authorizeRequests ->
     * 				authorizeRequests
     * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 			)
     * 			// sample exception handling customization
     * 			.exceptionHandling(exceptionHandling ->
     * 				exceptionHandling
     * 					.accessDeniedPage(&quot;/errors/access-denied&quot;)
     * 			);
     * 	}
     * }
     * </pre>
     *
     * @param exceptionHandlingCustomizer the {@link Customizer} to provide more options for
     * the {@link ExceptionHandlingConfigurer}
     * @return the {@link BspHttpSecurity} for further customizations
     * @throws Exception
     */
    public BspHttpSecurity exceptionHandling(Customizer<ExceptionHandlingConfigurer<BspHttpSecurity>> exceptionHandlingCustomizer) throws Exception {
        exceptionHandlingCustomizer.customize(getOrApply(new ExceptionHandlingConfigurer<>()));
        return BspHttpSecurity.this;
    }

    /**
     * Sets up management of the {@link SecurityContext} on the
     * {@link SecurityContextHolder} between {@link HttpServletRequest}'s. This is
     * automatically applied when using {@link WebSecurityConfigurerAdapter}.
     *
     * @return the {@link SecurityContextConfigurer} for further customizations
     * @throws Exception
     */
    public SecurityContextConfigurer<BspHttpSecurity> securityContext() throws Exception {
        return getOrApply(new SecurityContextConfigurer<>());
    }

    /**
     * Sets up management of the {@link SecurityContext} on the
     * {@link SecurityContextHolder} between {@link HttpServletRequest}'s. This is
     * automatically applied when using {@link WebSecurityConfigurerAdapter}.
     *
     * The following customization specifies the shared {@link SecurityContextRepository}
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class SecurityContextSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.securityContext(securityContext ->
     * 				securityContext
     * 					.securityContextRepository(SCR)
     * 			);
     * 	}
     * }
     * </pre>
     *
     * @param securityContextCustomizer the {@link Customizer} to provide more options for
     * the {@link SecurityContextConfigurer}
     * @return the {@link BspHttpSecurity} for further customizations
     * @throws Exception
     */
    public BspHttpSecurity securityContext(Customizer<SecurityContextConfigurer<BspHttpSecurity>> securityContextCustomizer) throws Exception {
        securityContextCustomizer.customize(getOrApply(new SecurityContextConfigurer<>()));
        return BspHttpSecurity.this;
    }

    /**
     * Integrates the {@link HttpServletRequest} methods with the values found on the
     * {@link SecurityContext}. This is automatically applied when using
     * {@link WebSecurityConfigurerAdapter}.
     *
     * @return the {@link ServletApiConfigurer} for further customizations
     * @throws Exception
     */
    public ServletApiConfigurer<BspHttpSecurity> servletApi() throws Exception {
        return getOrApply(new ServletApiConfigurer<>());
    }

    /**
     * Integrates the {@link HttpServletRequest} methods with the values found on the
     * {@link SecurityContext}. This is automatically applied when using
     * {@link WebSecurityConfigurerAdapter}. You can disable it using:
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class ServletApiSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.servletApi(servletApi ->
     * 				servletApi.disable()
     * 			);
     * 	}
     * }
     * </pre>
     *
     * @param servletApiCustomizer the {@link Customizer} to provide more options for
     * the {@link ServletApiConfigurer}
     * @return the {@link BspHttpSecurity} for further customizations
     * @throws Exception
     */
    public BspHttpSecurity servletApi(Customizer<ServletApiConfigurer<BspHttpSecurity>> servletApiCustomizer) throws Exception {
        servletApiCustomizer.customize(getOrApply(new ServletApiConfigurer<>()));
        return BspHttpSecurity.this;
    }

    /**
     * Adds CSRF support. This is activated by default when using
     * {@link WebSecurityConfigurerAdapter}'s default constructor. You can disable it
     * using:
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     *     protected void configure(BspHttpSecurity http) throws Exception {
     *         http
     *             .csrf().disable()
     *             ...;
     *     }
     * }
     * </pre>
     *
     * @return the {@link CsrfConfigurer} for further customizations
     * @throws Exception
     */
    public CsrfConfigurer<BspHttpSecurity> csrf() throws Exception {
        ApplicationContext context = getContext();
        return getOrApply(new CsrfConfigurer<>(context));
    }

    /**
     * Adds CSRF support. This is activated by default when using
     * {@link WebSecurityConfigurerAdapter}'s default constructor. You can disable it
     * using:
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     *     protected void configure(BspHttpSecurity http) throws Exception {
     *         http
     *             .csrf(csrf -> csrf.disable());
     *     }
     * }
     * </pre>
     *
     * @param csrfCustomizer the {@link Customizer} to provide more options for
     * the {@link CsrfConfigurer}
     * @return the {@link BspHttpSecurity} for further customizations
     * @throws Exception
     */
    public BspHttpSecurity csrf(Customizer<CsrfConfigurer<BspHttpSecurity>> csrfCustomizer) throws Exception {
        ApplicationContext context = getContext();
        csrfCustomizer.customize(getOrApply(new CsrfConfigurer<>(context)));
        return BspHttpSecurity.this;
    }

    /**
     * Provides logout support. This is automatically applied when using
     * {@link WebSecurityConfigurerAdapter}. The default is that accessing the URL
     * "/logout" will log the user out by invalidating the HTTP Session, cleaning up any
     * {@link #rememberMe()} authentication that was configured, clearing the
     * {@link SecurityContextHolder}, and then redirect to "/login?success".
     *
     * <h2>Example Custom Configuration</h2>
     *
     * The following customization to log out when the URL "/custom-logout" is invoked.
     * Log out will remove the cookie named "remove", not invalidate the HttpSession,
     * clear the SecurityContextHolder, and upon completion redirect to "/logout-success".
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class LogoutSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
     * 				.and()
     * 				// sample logout customization
     * 				.logout().deleteCookies(&quot;remove&quot;).invalidateHttpSession(false)
     * 				.logoutUrl(&quot;/custom-logout&quot;).logoutSuccessUrl(&quot;/logout-success&quot;);
     * 	}
     *
     * 	&#064;Override
     * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
     * 	}
     * }
     * </pre>
     *
     * @return the {@link LogoutConfigurer} for further customizations
     * @throws Exception
     */
    public LogoutConfigurer<BspHttpSecurity> logout() throws Exception {
        return getOrApply(new LogoutConfigurer<>());
    }

    /**
     * Provides logout support. This is automatically applied when using
     * {@link WebSecurityConfigurerAdapter}. The default is that accessing the URL
     * "/logout" will log the user out by invalidating the HTTP Session, cleaning up any
     * {@link #rememberMe()} authentication that was configured, clearing the
     * {@link SecurityContextHolder}, and then redirect to "/login?success".
     *
     * <h2>Example Custom Configuration</h2>
     *
     * The following customization to log out when the URL "/custom-logout" is invoked.
     * Log out will remove the cookie named "remove", not invalidate the HttpSession,
     * clear the SecurityContextHolder, and upon completion redirect to "/logout-success".
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class LogoutSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.authorizeRequests(authorizeRequests ->
     * 				authorizeRequests
     * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 			)
     * 			.formLogin(withDefaults())
     * 			// sample logout customization
     * 			.logout(logout ->
     * 				logout.deleteCookies(&quot;remove&quot;)
     * 					.invalidateHttpSession(false)
     * 					.logoutUrl(&quot;/custom-logout&quot;)
     * 					.logoutSuccessUrl(&quot;/logout-success&quot;)
     * 			);
     * 	}
     * }
     * </pre>
     *
     * @param logoutCustomizer the {@link Customizer} to provide more options for
     * the {@link LogoutConfigurer}
     * @return the {@link BspHttpSecurity} for further customizations
     * @throws Exception
     */
    public BspHttpSecurity logout(Customizer<LogoutConfigurer<BspHttpSecurity>> logoutCustomizer) throws Exception {
        logoutCustomizer.customize(getOrApply(new LogoutConfigurer<>()));
        return BspHttpSecurity.this;
    }

    /**
     * Allows configuring how an anonymous user is represented. This is automatically
     * applied when used in conjunction with {@link WebSecurityConfigurerAdapter}. By
     * default anonymous users will be represented with an
     * {@link org.springframework.security.authentication.AnonymousAuthenticationToken}
     * and contain the role "ROLE_ANONYMOUS".
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration demonstrates how to specify that anonymous users should
     * contain the role "ROLE_ANON" instead.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class AnonymousSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.authorizeRequests()
     * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 				.and()
     * 			.formLogin()
     * 				.and()
     * 			// sample anonymous customization
     * 			.anonymous().authorities(&quot;ROLE_ANON&quot;);
     * 	}
     *
     * 	&#064;Override
     * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
     * 	}
     * }
     * </pre>
     *
     * The following demonstrates how to represent anonymous users as null. Note that this
     * can cause {@link NullPointerException} in code that assumes anonymous
     * authentication is enabled.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class AnonymousSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.authorizeRequests()
     * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 				.and()
     * 			.formLogin()
     * 				.and()
     * 			// sample anonymous customization
     * 			.anonymous().disable();
     * 	}
     *
     * 	&#064;Override
     * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
     * 	}
     * }
     * </pre>
     *
     * @return the {@link AnonymousConfigurer} for further customizations
     * @throws Exception
     */
    public AnonymousConfigurer<BspHttpSecurity> anonymous() throws Exception {
        return getOrApply(new AnonymousConfigurer<>());
    }

    /**
     * Allows configuring how an anonymous user is represented. This is automatically
     * applied when used in conjunction with {@link WebSecurityConfigurerAdapter}. By
     * default anonymous users will be represented with an
     * {@link org.springframework.security.authentication.AnonymousAuthenticationToken}
     * and contain the role "ROLE_ANONYMOUS".
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration demonstrates how to specify that anonymous users should
     * contain the role "ROLE_ANON" instead.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class AnonymousSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.authorizeRequests(authorizeRequests ->
     * 				authorizeRequests
     * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 			)
     * 			.formLogin(withDefaults())
     * 			// sample anonymous customization
     * 			.anonymous(anonymous ->
     * 				anonymous
     * 					.authorities(&quot;ROLE_ANON&quot;)
     * 			)
     * 	}
     * }
     * </pre>
     *
     * The following demonstrates how to represent anonymous users as null. Note that this
     * can cause {@link NullPointerException} in code that assumes anonymous
     * authentication is enabled.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class AnonymousSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.authorizeRequests(authorizeRequests ->
     * 				authorizeRequests
     * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 			)
     * 			.formLogin(withDefaults())
     * 			// sample anonymous customization
     * 			.anonymous(anonymous ->
     * 				anonymous.disable()
     * 			);
     * 	}
     *
     * 	&#064;Override
     * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
     * 	}
     * }
     * </pre>
     *
     * @param anonymousCustomizer the {@link Customizer} to provide more options for
     * the {@link AnonymousConfigurer}
     * @return the {@link BspHttpSecurity} for further customizations
     * @throws Exception
     */
    public BspHttpSecurity anonymous(Customizer<AnonymousConfigurer<BspHttpSecurity>> anonymousCustomizer) throws Exception {
        anonymousCustomizer.customize(getOrApply(new AnonymousConfigurer<>()));
        return BspHttpSecurity.this;
    }


    /**
     * Specifies to support form based authentication. If
     * {@link BspFormLoginConfigurer#loginPage(String)} is not specified a default login page
     * will be generated.
     *
     * <h2>Example Configurations</h2>
     *
     * The most basic configuration defaults to automatically generating a login page at
     * the URL "/login", redirecting to "/login?error" for authentication failure. The
     * details of the login page can be found on
     * {@link BspFormLoginConfigurer#loginPage(String)}
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin();
     * 	}
     *
     * 	&#064;Override
     * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
     * 	}
     * }
     * </pre>
     *
     * The configuration below demonstrates customizing the defaults.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
     * 				.usernameParameter(&quot;username&quot;) // default is username
     * 				.passwordParameter(&quot;password&quot;) // default is password
     * 				.loginPage(&quot;/authentication/login&quot;) // default is /login with an HTTP get
     * 				.failureUrl(&quot;/authentication/login?failed&quot;) // default is /login?error
     * 				.loginProcessingUrl(&quot;/authentication/login/process&quot;); // default is /login
     * 																		// with an HTTP
     * 																		// post
     * 	}
     *
     * 	&#064;Override
     * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
     * 	}
     * }
     * </pre>
     *
     * @see BspFormLoginConfigurer#loginPage(String)
     *
     * @return the {@link BspFormLoginConfigurer} for further customizations
     * @throws Exception
     */
    public BspFormLoginConfigurer<BspHttpSecurity> formLogin() throws Exception {
        return getOrApply(new BspFormLoginConfigurer<>());
    }

    /**
     * Specifies to support form based authentication. If
     * {@link BspFormLoginConfigurer#loginPage(String)} is not specified a default login page
     * will be generated.
     *
     * <h2>Example Configurations</h2>
     *
     * The most basic configuration defaults to automatically generating a login page at
     * the URL "/login", redirecting to "/login?error" for authentication failure. The
     * details of the login page can be found on
     * {@link BspFormLoginConfigurer#loginPage(String)}
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.authorizeRequests(authorizeRequests ->
     * 				authorizeRequests
     * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 			)
     * 			.formLogin(withDefaults());
     * 	}
     * }
     * </pre>
     *
     * The configuration below demonstrates customizing the defaults.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.authorizeRequests(authorizeRequests ->
     * 				authorizeRequests
     * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 			)
     * 			.formLogin(formLogin ->
     * 				formLogin
     * 					.usernameParameter(&quot;username&quot;)
     * 					.passwordParameter(&quot;password&quot;)
     * 					.loginPage(&quot;/authentication/login&quot;)
     * 					.failureUrl(&quot;/authentication/login?failed&quot;)
     * 					.loginProcessingUrl(&quot;/authentication/login/process&quot;)
     * 			);
     * 	}
     * }
     * </pre>
     *
     * @see BspFormLoginConfigurer#loginPage(String)
     *
     * @param formLoginCustomizer the {@link Customizer} to provide more options for
     * the {@link BspFormLoginConfigurer}
     * @return the {@link BspHttpSecurity} for further customizations
     * @throws Exception
     */
    public BspHttpSecurity formLogin(Customizer<BspFormLoginConfigurer<BspHttpSecurity>> formLoginCustomizer) throws Exception {
        formLoginCustomizer.customize(getOrApply(new BspFormLoginConfigurer<>()));
        return BspHttpSecurity.this;
    }

    /**
     * Configures channel security. In order for this configuration to be useful at least
     * one mapping to a required channel must be provided.
     *
     * <h2>Example Configuration</h2>
     *
     * The example below demonstrates how to require HTTPs for every request. Only
     * requiring HTTPS for some requests is supported, but not recommended since an
     * application that allows for HTTP introduces many security vulnerabilities. For one
     * such example, read about <a
     * href="https://en.wikipedia.org/wiki/Firesheep">Firesheep</a>.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class ChannelSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
     * 				.and().requiresChannel().anyRequest().requiresSecure();
     * 	}
     *
     * 	&#064;Override
     * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
     * 	}
     * }
     * </pre>
     *
     *
     * @return the {@link ChannelSecurityConfigurer} for further customizations
     * @throws Exception
     */
    public ChannelSecurityConfigurer<BspHttpSecurity>.ChannelRequestMatcherRegistry requiresChannel()
            throws Exception {
        ApplicationContext context = getContext();
        return getOrApply(new ChannelSecurityConfigurer<>(context))
                .getRegistry();
    }

    /**
     * Configures channel security. In order for this configuration to be useful at least
     * one mapping to a required channel must be provided.
     *
     * <h2>Example Configuration</h2>
     *
     * The example below demonstrates how to require HTTPs for every request. Only
     * requiring HTTPS for some requests is supported, but not recommended since an
     * application that allows for HTTP introduces many security vulnerabilities. For one
     * such example, read about <a
     * href="https://en.wikipedia.org/wiki/Firesheep">Firesheep</a>.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class ChannelSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.authorizeRequests(authorizeRequests ->
     * 				authorizeRequests
     * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 			)
     * 			.formLogin(withDefaults())
     * 			.requiresChannel(requiresChannel ->
     * 				requiresChannel
     * 					.anyRequest().requiresSecure()
     * 			);
     * 	}
     * }
     * </pre>
     *
     * @param requiresChannelCustomizer the {@link Customizer} to provide more options for
     * the {@link ChannelSecurityConfigurer.ChannelRequestMatcherRegistry}
     * @return the {@link BspHttpSecurity} for further customizations
     * @throws Exception
     */
    public BspHttpSecurity requiresChannel(Customizer<ChannelSecurityConfigurer<BspHttpSecurity>.ChannelRequestMatcherRegistry> requiresChannelCustomizer)
            throws Exception {
        ApplicationContext context = getContext();
        requiresChannelCustomizer.customize(getOrApply(new ChannelSecurityConfigurer<>(context))
                .getRegistry());
        return BspHttpSecurity.this;
    }

    /**
     * Configures HTTP Basic authentication.
     *
     * <h2>Example Configuration</h2>
     *
     * The example below demonstrates how to configure HTTP Basic authentication for an
     * application. The default realm is "Realm", but can be
     * customized using {@link HttpBasicConfigurer#realmName(String)}.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class HttpBasicSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().httpBasic();
     * 	}
     *
     * 	&#064;Override
     * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
     * 	}
     * }
     * </pre>
     *
     * @return the {@link HttpBasicConfigurer} for further customizations
     * @throws Exception
     */
    public HttpBasicConfigurer<BspHttpSecurity> httpBasic() throws Exception {
        return getOrApply(new HttpBasicConfigurer<>());
    }

    /**
     * Configures HTTP Basic authentication.
     *
     * <h2>Example Configuration</h2>
     *
     * The example below demonstrates how to configure HTTP Basic authentication for an
     * application. The default realm is "Realm", but can be
     * customized using {@link HttpBasicConfigurer#realmName(String)}.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class HttpBasicSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.authorizeRequests(authorizeRequests ->
     * 				authorizeRequests
     * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 			)
     * 			.httpBasic(withDefaults());
     * 	}
     * }
     * </pre>
     *
     * @param httpBasicCustomizer the {@link Customizer} to provide more options for
     * the {@link HttpBasicConfigurer}
     * @return the {@link BspHttpSecurity} for further customizations
     * @throws Exception
     */
    public BspHttpSecurity httpBasic(Customizer<HttpBasicConfigurer<BspHttpSecurity>> httpBasicCustomizer) throws Exception {
        httpBasicCustomizer.customize(getOrApply(new HttpBasicConfigurer<>()));
        return BspHttpSecurity.this;
    }

    public <C> void setSharedObject(Class<C> sharedType, C object) {
        super.setSharedObject(sharedType, object);
    }

    @Override
    protected void beforeConfigure() throws Exception {
        setSharedObject(AuthenticationManager.class, getAuthenticationRegistry().build());
    }

    @Override
    protected DefaultSecurityFilterChain performBuild() {
        filters.sort(comparator);
        return new DefaultSecurityFilterChain(requestMatcher, filters);
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.springframework.security.config.annotation.web.HttpSecurityBuilder#authenticationProvider
     * (org.springframework.security.authentication.AuthenticationProvider)
     */
    public BspHttpSecurity authenticationProvider(
            AuthenticationProvider authenticationProvider) {
        getAuthenticationRegistry().authenticationProvider(authenticationProvider);
        return this;
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.springframework.security.config.annotation.web.HttpSecurityBuilder#userDetailsService
     * (org.springframework.security.core.userdetails.UserDetailsService)
     */
    public BspHttpSecurity userDetailsService(UserDetailsService userDetailsService)
            throws Exception {
        getAuthenticationRegistry().userDetailsService(userDetailsService);
        return this;
    }

    private AuthenticationManagerBuilder getAuthenticationRegistry() {
        return getSharedObject(AuthenticationManagerBuilder.class);
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.springframework.security.config.annotation.web.HttpSecurityBuilder#addFilterAfter(javax
     * .servlet.Filter, java.lang.Class)
     */
    public BspHttpSecurity addFilterAfter(Filter filter, Class<? extends Filter> afterFilter) {
        comparator.registerAfter(filter.getClass(), afterFilter);
        return addFilter(filter);
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.springframework.security.config.annotation.web.HttpSecurityBuilder#addFilterBefore(
     * javax.servlet.Filter, java.lang.Class)
     */
    public BspHttpSecurity addFilterBefore(Filter filter,
                                        Class<? extends Filter> beforeFilter) {
        comparator.registerBefore(filter.getClass(), beforeFilter);
        return addFilter(filter);
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.springframework.security.config.annotation.web.HttpSecurityBuilder#addFilter(javax.
     * servlet.Filter)
     */
    public BspHttpSecurity addFilter(Filter filter) {
        Class<? extends Filter> filterClass = filter.getClass();
        if (!comparator.isRegistered(filterClass)) {
            throw new IllegalArgumentException(
                    "The Filter class "
                            + filterClass.getName()
                            + " does not have a registered order and cannot be added without a specified order. Consider using addFilterBefore or addFilterAfter instead.");
        }
        this.filters.add(filter);
        return this;
    }

    /**
     * Adds the Filter at the location of the specified Filter class. For example, if you
     * want the filter CustomFilter to be registered in the same position as
     * {@link UsernamePasswordAuthenticationFilter}, you can invoke:
     *
     * <pre>
     * addFilterAt(new CustomFilter(), UsernamePasswordAuthenticationFilter.class)
     * </pre>
     *
     * Registration of multiple Filters in the same location means their ordering is not
     * deterministic. More concretely, registering multiple Filters in the same location
     * does not override existing Filters. Instead, do not register Filters you do not
     * want to use.
     *
     * @param filter the Filter to register
     * @param atFilter the location of another {@link Filter} that is already registered
     * (i.e. known) with Spring Security.
     * @return the {@link BspHttpSecurity} for further customizations
     */
    public BspHttpSecurity addFilterAt(Filter filter, Class<? extends Filter> atFilter) {
        this.comparator.registerAt(filter.getClass(), atFilter);
        return addFilter(filter);
    }

    /**
     * Allows specifying which {@link HttpServletRequest} instances this
     * {@link BspHttpSecurity} will be invoked on. This method allows for easily invoking the
     * {@link BspHttpSecurity} for multiple different {@link RequestMatcher} instances. If
     * only a single {@link RequestMatcher} is necessary consider using {@link #mvcMatcher(String)},
     * {@link #antMatcher(String)}, {@link #regexMatcher(String)}, or
     * {@link #requestMatcher(RequestMatcher)}.
     *
     * <p>
     * Invoking {@link #requestMatchers()} will not override previous invocations of {@link #mvcMatcher(String)}},
     * {@link #requestMatchers()}, {@link #antMatcher(String)},
     * {@link #regexMatcher(String)}, and {@link #requestMatcher(RequestMatcher)}.
     * </p>
     *
     * <h3>Example Configurations</h3>
     *
     * The following configuration enables the {@link BspHttpSecurity} for URLs that begin
     * with "/api/" or "/oauth/".
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.requestMatchers()
     * 				.antMatchers(&quot;/api/**&quot;, &quot;/oauth/**&quot;)
     * 				.and()
     * 			.authorizeRequests()
     * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 				.and()
     * 			.httpBasic();
     * 	}
     *
     * 	&#064;Override
     * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     * 		auth
     * 			.inMemoryAuthentication()
     * 				.withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
     * 	}
     * }
     * </pre>
     *
     * The configuration below is the same as the previous configuration.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.requestMatchers()
     * 				.antMatchers(&quot;/api/**&quot;)
     * 				.antMatchers(&quot;/oauth/**&quot;)
     * 				.and()
     * 			.authorizeRequests()
     * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 				.and()
     * 			.httpBasic();
     * 	}
     *
     * 	&#064;Override
     * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     * 		auth
     * 			.inMemoryAuthentication()
     * 				.withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
     * 	}
     * }
     * </pre>
     *
     * The configuration below is also the same as the above configuration.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.requestMatchers()
     * 				.antMatchers(&quot;/api/**&quot;)
     * 				.and()
     *			 .requestMatchers()
     * 				.antMatchers(&quot;/oauth/**&quot;)
     * 				.and()
     * 			.authorizeRequests()
     * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 				.and()
     * 			.httpBasic();
     * 	}
     *
     * 	&#064;Override
     * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     * 		auth
     * 			.inMemoryAuthentication()
     * 				.withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
     * 	}
     * }
     * </pre>
     *
     * @return the {@link BspHttpSecurity.RequestMatcherConfigurer} for further customizations
     */
    public BspHttpSecurity.RequestMatcherConfigurer requestMatchers() {
        return requestMatcherConfigurer;
    }

    /**
     * Allows specifying which {@link HttpServletRequest} instances this
     * {@link BspHttpSecurity} will be invoked on. This method allows for easily invoking the
     * {@link BspHttpSecurity} for multiple different {@link RequestMatcher} instances. If
     * only a single {@link RequestMatcher} is necessary consider using {@link #mvcMatcher(String)},
     * {@link #antMatcher(String)}, {@link #regexMatcher(String)}, or
     * {@link #requestMatcher(RequestMatcher)}.
     *
     * <p>
     * Invoking {@link #requestMatchers()} will not override previous invocations of {@link #mvcMatcher(String)}},
     * {@link #requestMatchers()}, {@link #antMatcher(String)},
     * {@link #regexMatcher(String)}, and {@link #requestMatcher(RequestMatcher)}.
     * </p>
     *
     * <h3>Example Configurations</h3>
     *
     * The following configuration enables the {@link BspHttpSecurity} for URLs that begin
     * with "/api/" or "/oauth/".
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.requestMatchers(requestMatchers ->
     * 				requestMatchers
     * 					.antMatchers(&quot;/api/**&quot;, &quot;/oauth/**&quot;)
     * 			)
     * 			.authorizeRequests(authorizeRequests ->
     * 				authorizeRequests
     * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 			)
     * 			.httpBasic(withDefaults());
     * 	}
     * }
     * </pre>
     *
     * The configuration below is the same as the previous configuration.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.requestMatchers(requestMatchers ->
     * 				requestMatchers
     * 					.antMatchers(&quot;/api/**&quot;)
     * 					.antMatchers(&quot;/oauth/**&quot;)
     * 			)
     * 			.authorizeRequests(authorizeRequests ->
     * 				authorizeRequests
     * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 			)
     * 			.httpBasic(withDefaults());
     * 	}
     * }
     * </pre>
     *
     * The configuration below is also the same as the above configuration.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     * 	protected void configure(BspHttpSecurity http) throws Exception {
     * 		http
     * 			.requestMatchers(requestMatchers ->
     * 				requestMatchers
     * 					.antMatchers(&quot;/api/**&quot;)
     * 			)
     *			.requestMatchers(requestMatchers ->
     *			requestMatchers
     * 				.antMatchers(&quot;/oauth/**&quot;)
     * 			)
     * 			.authorizeRequests(authorizeRequests ->
     * 				authorizeRequests
     * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     * 			)
     * 			.httpBasic(withDefaults());
     * 	}
     * }
     * </pre>
     *
     * @param requestMatcherCustomizer the {@link Customizer} to provide more options for
     * the {@link BspHttpSecurity.RequestMatcherConfigurer}
     * @return the {@link BspHttpSecurity} for further customizations
     */
    public BspHttpSecurity requestMatchers(Customizer<BspHttpSecurity.RequestMatcherConfigurer> requestMatcherCustomizer) {
        requestMatcherCustomizer.customize(requestMatcherConfigurer);
        return BspHttpSecurity.this;
    }

    /**
     * Allows configuring the {@link BspHttpSecurity} to only be invoked when matching the
     * provided {@link RequestMatcher}. If more advanced configuration is necessary,
     * consider using {@link #requestMatchers()}.
     *
     * <p>
     * Invoking {@link #requestMatcher(RequestMatcher)} will override previous invocations
     * of {@link #requestMatchers()}, {@link #mvcMatcher(String)}, {@link #antMatcher(String)},
     * {@link #regexMatcher(String)}, and {@link #requestMatcher(RequestMatcher)}.
     * </p>
     *
     * @param requestMatcher the {@link RequestMatcher} to use (i.e. new
     * AntPathRequestMatcher("/admin/**","GET") )
     * @return the {@link BspHttpSecurity} for further customizations
     * @see #requestMatchers()
     * @see #antMatcher(String)
     * @see #regexMatcher(String)
     */
    public BspHttpSecurity requestMatcher(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
        return this;
    }

    /**
     * Allows configuring the {@link BspHttpSecurity} to only be invoked when matching the
     * provided ant pattern. If more advanced configuration is necessary, consider using
     * {@link #requestMatchers()} or {@link #requestMatcher(RequestMatcher)}.
     *
     * <p>
     * Invoking {@link #antMatcher(String)} will override previous invocations of {@link #mvcMatcher(String)}},
     * {@link #requestMatchers()}, {@link #antMatcher(String)},
     * {@link #regexMatcher(String)}, and {@link #requestMatcher(RequestMatcher)}.
     * </p>
     *
     * @param antPattern the Ant Pattern to match on (i.e. "/admin/**")
     * @return the {@link BspHttpSecurity} for further customizations
     * @see AntPathRequestMatcher
     */
    public BspHttpSecurity antMatcher(String antPattern) {
        return requestMatcher(new AntPathRequestMatcher(antPattern));
    }

    /**
     * Allows configuring the {@link BspHttpSecurity} to only be invoked when matching the
     * provided regex pattern. If more advanced configuration is necessary, consider using
     * {@link #requestMatchers()} or {@link #requestMatcher(RequestMatcher)}.
     *
     * <p>
     * Invoking {@link #regexMatcher(String)} will override previous invocations of {@link #mvcMatcher(String)}},
     * {@link #requestMatchers()}, {@link #antMatcher(String)},
     * {@link #regexMatcher(String)}, and {@link #requestMatcher(RequestMatcher)}.
     * </p>
     *
     * @param pattern the Regular Expression to match on (i.e. "/admin/.+")
     * @return the {@link BspHttpSecurity} for further customizations
     * @see RegexRequestMatcher
     */
    public BspHttpSecurity regexMatcher(String pattern) {
        return requestMatcher(new RegexRequestMatcher(pattern, null));
    }

    /**
     * An extension to {@link BspHttpSecurity.RequestMatcherConfigurer} that allows optionally configuring
     * the servlet path.
     *
     * @author Rob Winch
     */
    public final class MvcMatchersRequestMatcherConfigurer extends BspHttpSecurity.RequestMatcherConfigurer {

        /**
         * Creates a new instance
         * @param context the {@link ApplicationContext} to use
         * @param matchers the {@link MvcRequestMatcher} instances to set the servlet path
         * on if {@link #servletPath(String)} is set.
         */
        private MvcMatchersRequestMatcherConfigurer(ApplicationContext context,
                                                    List<MvcRequestMatcher> matchers) {
            super(context);
            this.matchers = new ArrayList<>(matchers);
        }

        public BspHttpSecurity.RequestMatcherConfigurer servletPath(String servletPath) {
            for (RequestMatcher matcher : this.matchers) {
                ((MvcRequestMatcher) matcher).setServletPath(servletPath);
            }
            return this;
        }

    }

    /**
     * Allows mapping HTTP requests that this {@link BspHttpSecurity} will be used for
     *
     * @author Rob Winch
     * @since 3.2
     */
    public class RequestMatcherConfigurer
            extends AbstractRequestMatcherRegistry<RequestMatcherConfigurer> {

        protected List<RequestMatcher> matchers = new ArrayList<>();

        /**
         * @param context
         */
        private RequestMatcherConfigurer(ApplicationContext context) {
            setApplicationContext(context);
        }

        @Override
        public BspHttpSecurity.MvcMatchersRequestMatcherConfigurer mvcMatchers(HttpMethod method,
                                                                            String... mvcPatterns) {
            List<MvcRequestMatcher> mvcMatchers = createMvcMatchers(method, mvcPatterns);
            setMatchers(mvcMatchers);
            return new BspHttpSecurity.MvcMatchersRequestMatcherConfigurer(getContext(), mvcMatchers);
        }

        @Override
        public BspHttpSecurity.MvcMatchersRequestMatcherConfigurer mvcMatchers(String... patterns) {
            return mvcMatchers(null, patterns);
        }

        @Override
        protected BspHttpSecurity.RequestMatcherConfigurer chainRequestMatchers(
                List<RequestMatcher> requestMatchers) {
            setMatchers(requestMatchers);
            return this;
        }

        private void setMatchers(List<? extends RequestMatcher> requestMatchers) {
            this.matchers.addAll(requestMatchers);
            requestMatcher(new OrRequestMatcher(this.matchers));
        }

        /**
         * Return the {@link BspHttpSecurity} for further customizations
         *
         * @return the {@link BspHttpSecurity} for further customizations
         */
        public BspHttpSecurity and() {
            return BspHttpSecurity.this;
        }

    }

    /**
     * If the {@link SecurityConfigurer} has already been specified get the original,
     * otherwise apply the new {@link SecurityConfigurerAdapter}.
     *
     * @param configurer the {@link SecurityConfigurer} to apply if one is not found for
     * this {@link SecurityConfigurer} class.
     * @return the current {@link SecurityConfigurer} for the configurer passed in
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    private <C extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, BspHttpSecurity>> C getOrApply(
            C configurer) throws Exception {
        C existingConfig = (C) getConfigurer(configurer.getClass());
        if (existingConfig != null) {
            return existingConfig;
        }
        return apply(configurer);
    }
    
}
