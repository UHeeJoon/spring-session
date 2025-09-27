package multitenant.security.policy.admin;

import java.util.List;
import multitenant.security.policy.domain.PolicyConditionType;
import multitenant.security.policy.domain.PolicyEffect;

public record PolicySummary(
    Long id,
    String name,
    PolicyConditionType conditionType,
    String conditionValue,
    PolicyEffect effect,
    int priority,
    boolean active,
    List<String> tenantIds,
    List<String> excludedTenantIds,
    List<String> groupIds,
    List<String> excludedGroupIds,
    List<String> userIds,
    List<String> excludedUserIds
) {
}
