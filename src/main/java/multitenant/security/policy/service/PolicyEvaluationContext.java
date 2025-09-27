package multitenant.security.policy.service;

import java.io.Serializable;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.Set;

public record PolicyEvaluationContext(
    String tenantId,
    String userId,
    Set<String> groupIds,
    String clientIp,
    String countryCode,
    ZonedDateTime requestDateTime
) implements Serializable {
  public PolicyEvaluationContext {
    groupIds = groupIds == null ? Collections.emptySet() : Set.copyOf(groupIds);
  }

  public boolean hasUser() {
    return userId != null && !userId.isBlank();
  }

  public boolean hasGroups() {
    return !groupIds.isEmpty();
  }
}
