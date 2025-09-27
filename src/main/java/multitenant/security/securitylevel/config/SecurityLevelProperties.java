package multitenant.security.securitylevel.config;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import multitenant.security.securitylevel.SecurityLevel;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.level")
public class SecurityLevelProperties {

  private Duration defaultTtl = Duration.ofMinutes(15);
  private int retentionEvents = 20;
  private Duration retentionWindow = Duration.ofHours(6);
  private Map<String, PolicyRule> policies = new HashMap<>();

  public SecurityLevelProperties() {
    policies.put("LOGIN_FAILURE", new PolicyRule(SecurityLevel.MEDIUM, Duration.ofMinutes(30)));
    policies.put("PASSWORD_RESET", new PolicyRule(SecurityLevel.HIGH, Duration.ofHours(1)));
    policies.put("SUSPICIOUS_IP", new PolicyRule(SecurityLevel.HIGH, Duration.ofHours(2)));
    policies.put("DEVICE_CHANGE", new PolicyRule(SecurityLevel.MEDIUM, Duration.ofMinutes(45)));
    policies.put("UNKNOWN", new PolicyRule(SecurityLevel.MEDIUM, Duration.ofMinutes(30)));
  }

  public Duration getDefaultTtl() {
    return defaultTtl;
  }

  public void setDefaultTtl(Duration defaultTtl) {
    this.defaultTtl = defaultTtl;
  }

  public int getRetentionEvents() {
    return retentionEvents;
  }

  public void setRetentionEvents(int retentionEvents) {
    this.retentionEvents = retentionEvents;
  }

  public Duration getRetentionWindow() {
    return retentionWindow;
  }

  public void setRetentionWindow(Duration retentionWindow) {
    this.retentionWindow = retentionWindow;
  }

  public Map<String, PolicyRule> getPolicies() {
    return policies;
  }

  public void setPolicies(Map<String, PolicyRule> policies) {
    this.policies = policies;
  }

  public PolicyRule policyFor(String actionType) {
    String key = actionType == null ? "UNKNOWN" : actionType.trim().toUpperCase();
    return policies.getOrDefault(key, policies.get("UNKNOWN"));
  }

  public record PolicyRule(SecurityLevel level, Duration ttl) {
  }
}
