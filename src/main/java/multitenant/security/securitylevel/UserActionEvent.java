package multitenant.security.securitylevel;

import java.time.Instant;

public record UserActionEvent(
    String tenantId,
    String userId,
    String actionType,
    String actionDetail,
    Instant timestamp
) {
}
