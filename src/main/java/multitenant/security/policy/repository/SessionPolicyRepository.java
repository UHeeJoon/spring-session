package multitenant.security.policy.repository;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import multitenant.security.policy.domain.PolicyScopeType;
import multitenant.security.policy.domain.SessionPolicy;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SessionPolicyRepository extends JpaRepository<SessionPolicy, Long> {

  @EntityGraph(attributePaths = "scopes")
  List<SessionPolicy> findByActiveTrueAndScopesScopeTypeAndScopesScopeValueOrderByPriorityDesc(
      PolicyScopeType scopeType, String scopeValue);

  @EntityGraph(attributePaths = "scopes")
  List<SessionPolicy> findAllByOrderByPriorityDesc();

  default List<SessionPolicy> findActiveForTenant(String tenantId) {
    List<SessionPolicy> policies =
        findByActiveTrueAndScopesScopeTypeAndScopesScopeValueOrderByPriorityDesc(
            PolicyScopeType.TENANT, tenantId);
    Set<SessionPolicy> distinct = new LinkedHashSet<>(policies);
    return distinct.stream()
        .sorted((a, b) -> Integer.compare(b.getPriority(), a.getPriority()))
        .toList();
  }
}
