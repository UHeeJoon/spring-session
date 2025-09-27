package multitenant.security.sessionlimit.repository;

import multitenant.security.sessionlimit.domain.TenantSessionLimit;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TenantSessionLimitRepository extends JpaRepository<TenantSessionLimit, String> {
}
