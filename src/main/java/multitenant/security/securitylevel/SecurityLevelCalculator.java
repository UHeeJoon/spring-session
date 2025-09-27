package multitenant.security.securitylevel;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumMap;
import java.util.Map;
import org.springframework.stereotype.Component;
import multitenant.security.securitylevel.config.SecurityLevelProperties;

@Component
public class SecurityLevelCalculator {

  private final Clock clock;
  private final SecurityLevelProperties properties;
  private final Map<SecurityLevel, Integer> scoreByLevel = new EnumMap<>(SecurityLevel.class);

  public SecurityLevelCalculator(Clock clock, SecurityLevelProperties properties) {
    this.clock = clock;
    this.properties = properties;
    scoreByLevel.put(SecurityLevel.LOW, 0);
    scoreByLevel.put(SecurityLevel.MEDIUM, 5);
    scoreByLevel.put(SecurityLevel.HIGH, 10);
  }

  public SecurityLevelState defaultState() {
    Instant now = clock.instant();
    return new SecurityLevelState(SecurityLevel.LOW, now.plus(properties.getDefaultTtl()), 0);
  }

  public SecurityLevelState refreshIfExpired(SecurityLevelState state) {
    Instant now = clock.instant();
    if (state == null || state.isExpired(now)) {
      return defaultState();
    }
    return state;
  }

  public SecurityLevelState applyEvent(SecurityLevelState current, UserActionEvent event) {
    SecurityLevelProperties.PolicyRule rule = properties.policyFor(event.actionType());
    SecurityLevelPolicy policy = new SecurityLevelPolicy(rule.level(), rule.ttl(), 0);
    int baseScore = current == null ? 0 : current.score();
    int newScore = baseScore + scoreByLevel.getOrDefault(policy.level(), 5);
    SecurityLevel derivedLevel = deriveLevel(newScore);
    SecurityLevel finalLevel = maxSeverity(derivedLevel, policy.level());
    Instant expiresAt = policy.expiresAt(event.timestamp());
    return new SecurityLevelState(finalLevel, expiresAt, newScore);
  }

  private SecurityLevel deriveLevel(int score) {
    if (score >= 15) {
      return SecurityLevel.HIGH;
    }
    if (score >= 5) {
      return SecurityLevel.MEDIUM;
    }
    return SecurityLevel.LOW;
  }

  private SecurityLevel maxSeverity(SecurityLevel first, SecurityLevel second) {
    return first.ordinal() >= second.ordinal() ? first : second;
  }
}
