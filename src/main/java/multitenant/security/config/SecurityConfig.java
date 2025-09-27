package multitenant.security.config;

import java.util.Map;
import java.util.Set;
import multitenant.security.policy.filter.SessionPolicyFilter;
import multitenant.security.security.TenantAuthenticationSuccessHandler;
import multitenant.security.security.TenantUserDetails;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.webauthn.registration.HttpSessionPublicKeyCredentialCreationOptionsRepository;
import org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsRepository;

@Configuration
public class SecurityConfig {

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http, SessionPolicyFilter sessionPolicyFilter)
      throws Exception {

    http
        .requestCache(RequestCacheConfigurer::disable)
        .authorizeHttpRequests((authz) -> authz
            .requestMatchers("/login", "/register", "/css/**", "/js/**", "/images/**")
            .permitAll()
            .anyRequest().authenticated()
        )
        .formLogin(form -> form
            .loginPage("/login")
            .successHandler(authenticationSuccessHandler())
            .permitAll()
        )
        .logout(logout -> logout.logoutSuccessUrl("/login?logout"))
        .csrf(Customizer.withDefaults());
    http.webAuthn(w -> w
        .creationOptionsRepository(new HttpSessionPublicKeyCredentialCreationOptionsRepository())
        .rpId("localhost")
        .rpName("localhost")
    );
    http.addFilterAfter(sessionPolicyFilter, SecurityContextPersistenceFilter.class);
    return http.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  @Bean
  public UserDetailsService userDetailsService(PasswordEncoder encoder) {
    Map<String, TenantUserDetails> users = Map.of(
        "alice",
        new TenantUserDetails("alice", encoder.encode("password"), "tenant1",
            Set.of("engineering"), "KR", Set.of("USER")),
        "bob",
        new TenantUserDetails("bob", encoder.encode("password"), "tenant2",
            Set.of("sales"), "US", Set.of("USER")),
        "admin",
        new TenantUserDetails("admin", encoder.encode("admin123"), "tenant1",
            Set.of("engineering", "security"), "KR", Set.of("ADMIN"))
    );
    return username -> {
      TenantUserDetails details = users.get(username);
      if (details == null) {
        throw new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username);
      }
      return details;
    };
  }

  @Bean
  public AuthenticationSuccessHandler authenticationSuccessHandler() {
    return new TenantAuthenticationSuccessHandler();
  }

}
