package multitenant.security.policy.condition;

import multitenant.security.policy.domain.PolicyConditionType;
import multitenant.security.policy.domain.SessionPolicy;
import multitenant.security.policy.service.PolicyEvaluationContext;

public interface PolicyConditionEvaluator {

  boolean supports(PolicyConditionType conditionType);

  boolean matches(SessionPolicy policy, PolicyEvaluationContext context);
}
