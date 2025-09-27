package multitenant.security.policy.service;

import java.io.Serializable;
import multitenant.security.policy.domain.PolicyEffect;
import multitenant.security.policy.domain.SessionPolicy;

public record PolicyEvaluationResult(boolean allowed, Long policyId, PolicyEffect effect) implements
    Serializable {

  public static PolicyEvaluationResult allow(SessionPolicy policy) {
    return new PolicyEvaluationResult(true, policy == null ? null : policy.getId(),
        policy == null ? null : policy.getEffect());
  }

  public static PolicyEvaluationResult deny(SessionPolicy policy) {
    return new PolicyEvaluationResult(false, policy == null ? null : policy.getId(),
        policy == null ? null : policy.getEffect());
  }
}
