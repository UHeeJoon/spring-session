package multitenant.security.policy.admin;

import java.io.Serializable;
import multitenant.security.policy.domain.PolicyEffect;
import multitenant.security.policy.service.PolicyEvaluationContext;
import multitenant.security.policy.service.PolicyEvaluationResult;

public record PolicyTestOutcome(
    PolicyEvaluationContext context,
    PolicyEvaluationResult result
) implements Serializable {

  public String verdict() {
    return result.allowed() ? "허용" : "차단";
  }

  public String effectLabel() {
    PolicyEffect effect = result.effect();
    if (effect == null) {
      return "(기본 허용)";
    }
    return effect == PolicyEffect.ALLOW ? "ALLOW" : "DENY";
  }
}
