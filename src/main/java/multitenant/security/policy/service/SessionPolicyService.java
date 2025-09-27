package multitenant.security.policy.service;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import multitenant.security.policy.condition.PolicyConditionEvaluator;
import multitenant.security.policy.domain.PolicyConditionType;
import multitenant.security.policy.domain.PolicyEffect;
import multitenant.security.policy.domain.PolicyScopeType;
import multitenant.security.policy.domain.SessionPolicy;
import multitenant.security.policy.domain.SessionPolicyScope;
import multitenant.security.policy.repository.SessionPolicyRepository;
import org.springframework.stereotype.Service;

@Service
public class SessionPolicyService {

  private final SessionPolicyRepository sessionPolicyRepository;
  private final Map<PolicyConditionType, PolicyConditionEvaluator> evaluatorByType;

  public SessionPolicyService(SessionPolicyRepository sessionPolicyRepository,
      List<PolicyConditionEvaluator> evaluators) {
    this.sessionPolicyRepository = sessionPolicyRepository;
    this.evaluatorByType = new EnumMap<>(PolicyConditionType.class);
    evaluators.forEach(evaluator -> evaluatorByType.putIfAbsent(
        resolveType(evaluator), evaluator));
  }

  public PolicyEvaluationResult evaluate(PolicyEvaluationContext context) {
    if (context.tenantId() == null || context.tenantId().isBlank()) {
      return PolicyEvaluationResult.allow(null);
    }
    List<SessionPolicy> policies = sessionPolicyRepository.findActiveForTenant(context.tenantId());
    for (SessionPolicy policy : policies) {
      if (!scopeMatches(policy, context)) {
        continue;
      }
      PolicyConditionEvaluator evaluator = evaluatorByType.get(policy.getConditionType());
      if (evaluator == null) {
        continue;
      }
      if (!evaluator.matches(policy, context)) {
        continue;
      }
      if (policy.getEffect() == PolicyEffect.DENY) {
        return PolicyEvaluationResult.deny(policy);
      }
      return PolicyEvaluationResult.allow(policy);
    }
    return PolicyEvaluationResult.allow(null);
  }

  private boolean scopeMatches(SessionPolicy policy, PolicyEvaluationContext context) {
    Set<String> tenantScopes = collectScopeValues(policy, PolicyScopeType.TENANT, false);
    if (tenantScopes.isEmpty() || context.tenantId() == null) {
      return false;
    }
    if (!tenantScopes.contains(context.tenantId())) {
      return false;
    }

    Set<String> excludedTenants = collectScopeValues(policy, PolicyScopeType.TENANT, true);
    if (!excludedTenants.isEmpty() && excludedTenants.contains(context.tenantId())) {
      return false;
    }

    Set<String> userScopes = collectScopeValues(policy, PolicyScopeType.USER, false);
    if (!userScopes.isEmpty()) {
      if (!context.hasUser() || !userScopes.contains(context.userId())) {
        return false;
      }
    }

    Set<String> excludedUsers = collectScopeValues(policy, PolicyScopeType.USER, true);
    if (!excludedUsers.isEmpty() && context.hasUser() && excludedUsers.contains(context.userId())) {
      return false;
    }

    Set<String> groupScopes = collectScopeValues(policy, PolicyScopeType.GROUP, false);
    if (!groupScopes.isEmpty()) {
      if (!context.hasGroups() || context.groupIds().stream().noneMatch(groupScopes::contains)) {
        return false;
      }
    }
    Set<String> excludedGroups = collectScopeValues(policy, PolicyScopeType.GROUP, true);
    if (!excludedGroups.isEmpty() && context.hasGroups()
        && context.groupIds().stream().anyMatch(excludedGroups::contains)) {
      return false;
    }
    return true;
  }

  private Set<String> collectScopeValues(SessionPolicy policy, PolicyScopeType scopeType,
      boolean excluded) {
    return policy.getScopes().stream()
        .filter(scope -> scope.getScopeType() == scopeType && scope.isExcluded() == excluded)
        .map(SessionPolicyScope::getScopeValue)
        .collect(Collectors.toSet());
  }

  private PolicyConditionType resolveType(PolicyConditionEvaluator evaluator) {
    for (PolicyConditionType type : PolicyConditionType.values()) {
      if (evaluator.supports(type)) {
        return type;
      }
    }
    throw new IllegalArgumentException("No supported type for evaluator " + evaluator.getClass());
  }
}
