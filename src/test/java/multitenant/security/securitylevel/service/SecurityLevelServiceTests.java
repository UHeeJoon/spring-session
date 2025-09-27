package multitenant.security.securitylevel.service;

import static org.assertj.core.api.Assertions.assertThat;

import multitenant.security.securitylevel.SecurityLevel;
import multitenant.security.securitylevel.SecurityLevelState;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
@org.springframework.test.context.TestPropertySource(properties = "spring.task.scheduling.enabled=false")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class SecurityLevelServiceTests {

  @Autowired
  private SecurityLevelService securityLevelService;

  @Test
  void defaultsToLowLevelWithoutActions() {
    SecurityLevelState state = securityLevelService.currentLevel("tenant1", "alice");
    assertThat(state.level()).isEqualTo(SecurityLevel.LOW);
  }

  @Test
  void escalatesToHighAfterSuspiciousEvent() {
    securityLevelService.registerAction("tenant1", "alice", "SUSPICIOUS_IP", "국외 IP");
    SecurityLevel level = securityLevelService.resolveSecurityLevel("tenant1", "alice");
    assertThat(level).isEqualTo(SecurityLevel.HIGH);
  }
}
