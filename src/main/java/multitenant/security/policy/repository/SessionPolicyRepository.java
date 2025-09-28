package multitenant.security.policy.repository;

import java.util.List;
import multitenant.security.policy.domain.PolicyScopeType;
import multitenant.security.policy.domain.SessionPolicy;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SessionPolicyRepository extends JpaRepository<SessionPolicy, Long> {

  @Query("""
      select distinct p from SessionPolicy p
        left join fetch p.scopes s
      where p.active = true
        and exists (
          select 1 from SessionPolicyScope ts
          where ts.policy = p
            and ts.scopeType = :tenantScope
            and ts.scopeValue = :tenantId
            and ts.excluded = false
        )
      order by p.priority desc, p.id desc
      """)
  List<SessionPolicy> findActiveForTenantWithScopes(
      @Param("tenantId") String tenantId,
      @Param("tenantScope") PolicyScopeType tenantScope);

  @Query("""
      select distinct p from SessionPolicy p
        left join fetch p.scopes s
      order by p.priority desc, p.id desc
      """)
  List<SessionPolicy> findAllWithScopes();

  default List<SessionPolicy> findActiveForTenant(String tenantId) {
    return findActiveForTenantWithScopes(tenantId, PolicyScopeType.TENANT);
  }
}
