package AplicacionSegura.appsegura;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
          // Cabeceras de seguridad
          .headers(h -> h
            .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000)) // HSTS
            .contentSecurityPolicy(csp -> csp.policyDirectives(
                "default-src 'self'; " +
                "script-src 'self'; style-src 'self' 'unsafe-inline'; " +
                "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"))
            .referrerPolicy(r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
            .permissionsPolicy(p -> p.policy("geolocation=(), microphone=(), camera=()"))
          )

          // Autorización
          .authorizeHttpRequests(auth -> auth
            .requestMatchers("/login", "/mfa").permitAll()
            .requestMatchers("/hello").hasAnyRole("ADMIN","USER")
            .anyRequest().authenticated()
          )

          // Login/Logout
          .formLogin(form -> form
            .loginPage("/login")
            .defaultSuccessUrl("/mfa", true)   // MFA siempre tras login
            .permitAll()
          )
          .logout(logout -> logout
            .logoutSuccessUrl("/login?logout")
            .permitAll()
          );
        // CSRF queda ACTIVADO por defecto (correcto para tus formularios)
        return http.build();
    }
}
