package multitenant.security.securitylevel;

import java.time.Instant;

public record SecurityLevelState(
    SecurityLevel level,
    Instant expiresAt,
    int score
) {
  public boolean isExpired(Instant now) {
    return expiresAt != null && expiresAt.isBefore(now);
  }
}
