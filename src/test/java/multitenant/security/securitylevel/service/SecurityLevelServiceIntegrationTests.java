package multitenant.security.securitylevel.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import multitenant.security.securitylevel.SecurityLevel;
import multitenant.security.securitylevel.SecurityLevelState;
import multitenant.security.securitylevel.UserActionEvent;
import multitenant.security.securitylevel.config.SecurityLevelProperties;
import multitenant.security.securitylevel.persistence.SecurityLevelEventEntity;
import multitenant.security.securitylevel.persistence.SecurityLevelEventRepository;
import multitenant.security.securitylevel.persistence.SecurityLevelStateEntity;
import multitenant.security.securitylevel.persistence.SecurityLevelStateId;
import multitenant.security.securitylevel.persistence.SecurityLevelStateRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@ActiveProfiles("test")
@TestPropertySource(properties = {
    "security.level.default-ttl=PT10M",
    "security.level.retention-events=5",
    "security.level.retention-window=PT1H",
    "security.level.cleanup-interval=PT1H",
    "security.level.policies.LOGIN_FAILURE.level=MEDIUM",
    "security.level.policies.LOGIN_FAILURE.ttl=PT30M",
    "security.level.policies.SUSPICIOUS_IP.level=HIGH",
    "security.level.policies.SUSPICIOUS_IP.ttl=PT2H"
})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class SecurityLevelServiceIntegrationTests {

  @Autowired
  private SecurityLevelService securityLevelService;

  @Autowired
  private SecurityLevelStateRepository stateRepository;

  @Autowired
  private SecurityLevelEventRepository eventRepository;

  @Autowired
  private MutableClock testClock;

  @Autowired
  private SecurityLevelProperties properties;

  @Test
  void registerActionPersistsStateAndEventsWithConfiguredTtl() {
    Instant baseline = testClock.instant();

    SecurityLevelState state =
        securityLevelService.registerAction("tenantA", "user1", "LOGIN_FAILURE", "attempt 1");

    assertThat(state.level()).isEqualTo(SecurityLevel.MEDIUM);
    assertThat(state.expiresAt()).isEqualTo(baseline.plus(Duration.ofMinutes(30)));

    SecurityLevelStateEntity entity = stateRepository
        .findById(new SecurityLevelStateId("tenantA", "user1"))
        .orElseThrow();
    assertThat(entity.getLevel()).isEqualTo(SecurityLevel.MEDIUM);
    assertThat(entity.getExpiresAt()).isEqualTo(baseline.plus(Duration.ofMinutes(30)));

    List<SecurityLevelEventEntity> events =
        eventRepository.findByTenantIdAndUserIdOrderByOccurredAtDesc("tenantA", "user1",
            PageRequest.of(0, 10));
    assertThat(events).hasSize(1);
    assertThat(events.get(0).getActionType()).isEqualTo("LOGIN_FAILURE");
  }

  @Test
  void retentionPolicyKeepsMostRecentEventsOnly() {
    for (int i = 0; i < properties.getRetentionEvents() + 2; i++) {
      securityLevelService.registerAction("tenantB", "user2", "LOGIN_FAILURE", "event " + i);
      testClock.advance(Duration.ofMinutes(1));
    }

    List<SecurityLevelEventEntity> recentEvents =
        eventRepository.findByTenantIdAndUserIdOrderByOccurredAtDesc("tenantB", "user2",
            PageRequest.of(0, properties.getRetentionEvents()));

    assertThat(recentEvents).hasSize(properties.getRetentionEvents());
    SecurityLevelEventEntity oldestKept = recentEvents.get(recentEvents.size() - 1);
    int totalEvents = properties.getRetentionEvents() + 2;
    int expectedOldestIndex = totalEvents - properties.getRetentionEvents();
    assertThat(oldestKept.getActionDetail())
        .isEqualTo("event " + expectedOldestIndex);
  }

  @Test
  void cleanupRemovesExpiredStatesAndOldEvents() {
    securityLevelService.registerAction("tenantC", "user3", "SUSPICIOUS_IP", "flag");

    testClock.advance(Duration.ofHours(3));

    securityLevelService.cleanupExpiredData();

    assertThat(stateRepository.findById(new SecurityLevelStateId("tenantC", "user3"))).isEmpty();
    List<UserActionEvent> events = securityLevelService.recentActions("tenantC", "user3");
    assertThat(events).isEmpty();
  }

  @TestConfiguration
  static class ClockTestConfiguration {

    @Bean
    @Primary
    MutableClock testClock() {
      return new MutableClock(Instant.parse("2025-01-01T00:00:00Z"), ZoneOffset.UTC);
    }
  }

  static class MutableClock extends Clock {

    private Instant current;
    private final ZoneId zone;

    MutableClock(Instant current, ZoneId zone) {
      this.current = current;
      this.zone = zone;
    }

    void advance(Duration duration) {
      current = current.plus(duration);
    }

    @Override
    public ZoneId getZone() {
      return zone;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return new MutableClock(current, zone);
    }

    @Override
    public Instant instant() {
      return current;
    }
  }
}
