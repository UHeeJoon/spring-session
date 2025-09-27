package multitenant.security.sessionlimit.service;

import java.time.Duration;

public record SessionLimitSettings(int maxSessions, Duration maxIdle, Duration maxDuration) {

  public SessionLimitSettings {
    maxIdle = maxIdle == null ? Duration.ZERO : maxIdle;
    maxDuration = maxDuration == null ? Duration.ZERO : maxDuration;
  }

  public boolean hasMaxSessionsLimit() {
    return maxSessions > 0;
  }

  public boolean hasIdleLimit() {
    return maxIdle != null && !maxIdle.isNegative() && !maxIdle.isZero();
  }

  public boolean hasDurationLimit() {
    return maxDuration != null && !maxDuration.isNegative() && !maxDuration.isZero();
  }
}
