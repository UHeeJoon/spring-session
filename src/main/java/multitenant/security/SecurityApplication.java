package multitenant.security;

import java.time.Clock;
import multitenant.security.securitylevel.config.SecurityLevelProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties(SecurityLevelProperties.class)
public class SecurityApplication {

  public static void main(String[] args) {
    SpringApplication.run(SecurityApplication.class, args);
  }

  @Bean
  public Clock systemClock() {
    return Clock.systemUTC();
  }

}
