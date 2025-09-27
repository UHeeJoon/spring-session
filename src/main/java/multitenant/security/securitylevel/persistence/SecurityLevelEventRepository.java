package multitenant.security.securitylevel.persistence;

import java.time.Instant;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SecurityLevelEventRepository
    extends JpaRepository<SecurityLevelEventEntity, Long> {

  List<SecurityLevelEventEntity> findByTenantIdAndUserIdOrderByOccurredAtDesc(String tenantId,
      String userId, Pageable pageable);

  void deleteByTenantIdAndUserId(String tenantId, String userId);

  @Modifying
  @Query("delete from SecurityLevelEventEntity e where e.tenantId = :tenantId and e.userId = :userId and e.occurredAt < :cutoff")
  int deleteOlderThanForUser(@Param("tenantId") String tenantId, @Param("userId") String userId,
      @Param("cutoff") Instant cutoff);

  @Modifying
  @Query("delete from SecurityLevelEventEntity e where e.occurredAt < :cutoff")
  int deleteOlderThan(@Param("cutoff") Instant cutoff);
}
