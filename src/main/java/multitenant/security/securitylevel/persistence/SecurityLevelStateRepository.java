package multitenant.security.securitylevel.persistence;

import java.time.Instant;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SecurityLevelStateRepository extends JpaRepository<SecurityLevelStateEntity, SecurityLevelStateId> {

  @Modifying
  @Query("delete from SecurityLevelStateEntity s where s.expiresAt < :cutoff")
  int deleteExpired(@Param("cutoff") Instant cutoff);

  List<SecurityLevelStateEntity> findByTenantId(String tenantId);
}
