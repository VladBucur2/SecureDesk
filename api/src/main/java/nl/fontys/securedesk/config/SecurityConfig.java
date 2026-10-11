package nl.fontys.securedesk.config;

import nl.fontys.securedesk.audit.AuditLog;
import nl.fontys.securedesk.auth.AuthProperties;
import nl.fontys.securedesk.auth.AuthSessions;
import nl.fontys.securedesk.auth.SessionValidationFilter;
import nl.fontys.securedesk.user.AppUserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

import java.time.Clock;

/**
 * Function-level authorisation, deny by default (SC-03): a request is refused unless a rule below
 * permits it, and every controller method carries a {@code @PreAuthorize} check of its own as
 * well. The role rules here and the annotations there say the same thing twice on purpose; an
 * endpoint that forgets one is still covered by the other.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    /**
     * A synchroniser token bound to the session, read by the SPA from /api/auth/session and sent
     * back in the X-XSRF-TOKEN header. It dies with the session, so a request that still carries
     * the token of a session that was ended is refused (case 8 of BoK 6.1).
     */
    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-XSRF-TOKEN");
        return repository;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, SecurityContextRepository contextRepository,
                                           CsrfTokenRepository csrfTokenRepository, JsonSecurityHandlers handlers,
                                           AppUserRepository users, AuthSessions sessions, AuditLog audit,
                                           Clock clock, AuthProperties properties) throws Exception {
        http
            // No formLogin(): the two-step flow is handled by AuthController, so that a correct
            // password alone never produces an authenticated SecurityContext.
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable)
            .requestCache(AbstractHttpConfigurer::disable)
            .securityContext(context -> context.securityContextRepository(contextRepository))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
            .csrf(csrf -> csrf
                .csrfTokenRepository(csrfTokenRepository)
                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                .requestMatchers("/error").permitAll()
                // The sign-in endpoints check their own stage; /reauth requires a session by annotation.
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/queue/**").hasRole("AGENT")
                .requestMatchers("/api/tickets/**").hasRole("REQUESTER")
                .requestMatchers("/api/**").authenticated()
                .anyRequest().denyAll())
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(handlers)
                .accessDeniedHandler(handlers))
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'; sandbox")))
            .addFilterAfter(new SessionValidationFilter(users, sessions, audit, clock,
                    properties.absoluteSessionLifetime()), SecurityContextHolderFilter.class);
        return http.build();
    }
}
