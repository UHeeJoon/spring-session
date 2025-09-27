package multitenant.security.securitylevel;

import java.time.Duration;
import java.time.Instant;

public record SecurityLevelPolicy(
    SecurityLevel level,
    Duration ttl,
    int threshold
) {
  public SecurityLevelPolicy {
    if (level == null) {
      throw new IllegalArgumentException("보안 레벨이 지정되지 않았습니다.");
    }
    if (ttl == null || ttl.isNegative() || ttl.isZero()) {
      throw new IllegalArgumentException("TTL은 0보다 길어야 합니다.");
    }
    if (threshold < 0) {
      throw new IllegalArgumentException("임계값은 0 이상이어야 합니다.");
    }
  }

  public Instant expiresAt(Instant now) {
    return now.plus(ttl);
  }
}
