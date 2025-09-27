package multitenant.security.sessionlimit.service;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import multitenant.security.sessionlimit.domain.TenantSessionLimit;
import multitenant.security.sessionlimit.repository.TenantSessionLimitRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@Transactional
public class TenantSessionLimitService {

  public static final String SESSION_INDEX_KEY_ATTRIBUTE =
      org.springframework.session.FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME;

  private static final int DEFAULT_MAX_SESSIONS = 0;
  private static final Duration DEFAULT_MAX_IDLE = Duration.ofSeconds(1800);
  private static final Duration DEFAULT_MAX_DURATION = Duration.ZERO;

  private final TenantSessionLimitRepository repository;

  public TenantSessionLimitService(TenantSessionLimitRepository repository) {
    this.repository = repository;
  }

  @Transactional(readOnly = true)
  public SessionLimitSettings resolveForTenant(String tenantId) {
    if (!StringUtils.hasText(tenantId)) {
      return defaultSettings();
    }
    String normalized = tenantId.trim();
    Optional<TenantSessionLimit> found = repository.findById(normalized);
    return found.map(this::toSettings).orElse(defaultSettings());
  }

  @Transactional(readOnly = true)
  public List<TenantSessionLimit> findAll() {
    return repository.findAll();
  }

  public TenantSessionLimit upsert(String tenantId, int maxSessions, int maxIdleSeconds,
      int maxDurationSeconds) {
    if (!StringUtils.hasText(tenantId)) {
      throw new IllegalArgumentException("테넌트 ID는 필수입니다.");
    }
    String normalized = tenantId.trim();
    TenantSessionLimit entity = repository.findById(normalized)
        .orElseGet(() -> new TenantSessionLimit(normalized, DEFAULT_MAX_SESSIONS,
            (int) DEFAULT_MAX_IDLE.getSeconds(),
            (int) DEFAULT_MAX_DURATION.getSeconds()));
    entity.setMaxSessions(Math.max(0, maxSessions));
    entity.setMaxIdleSeconds(Math.max(0, maxIdleSeconds));
    entity.setMaxDurationSeconds(Math.max(0, maxDurationSeconds));
    return repository.save(entity);
  }

  public SessionLimitSettings defaultSettings() {
    return new SessionLimitSettings(DEFAULT_MAX_SESSIONS, DEFAULT_MAX_IDLE, DEFAULT_MAX_DURATION);
  }

  private SessionLimitSettings toSettings(TenantSessionLimit entity) {
    Duration idle = secondsToDuration(entity.getMaxIdleSeconds(), DEFAULT_MAX_IDLE);
    Duration duration = secondsToDuration(entity.getMaxDurationSeconds(), DEFAULT_MAX_DURATION);
    int maxSessions = Math.max(0, entity.getMaxSessions());
    return new SessionLimitSettings(maxSessions, idle, duration);
  }

  private Duration secondsToDuration(int value, Duration fallback) {
    if (value < 0) {
      return fallback;
    }
    if (value == 0) {
      return Duration.ZERO;
    }
    return Duration.ofSeconds(value);
  }
}
