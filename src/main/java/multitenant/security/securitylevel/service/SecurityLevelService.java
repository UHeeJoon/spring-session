package multitenant.security.securitylevel.service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import multitenant.security.securitylevel.SecurityLevel;
import multitenant.security.securitylevel.SecurityLevelCalculator;
import multitenant.security.securitylevel.SecurityLevelState;
import multitenant.security.securitylevel.UserActionEvent;
import multitenant.security.securitylevel.config.SecurityLevelProperties;
import multitenant.security.securitylevel.persistence.SecurityLevelEventEntity;
import multitenant.security.securitylevel.persistence.SecurityLevelEventRepository;
import multitenant.security.securitylevel.persistence.SecurityLevelStateEntity;
import multitenant.security.securitylevel.persistence.SecurityLevelStateId;
import multitenant.security.securitylevel.persistence.SecurityLevelStateRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@Transactional
public class SecurityLevelService {

  private final SecurityLevelCalculator calculator;
  private final SecurityLevelStateRepository stateRepository;
  private final SecurityLevelEventRepository eventRepository;
  private final SecurityLevelProperties properties;
  private final Clock clock;

  public SecurityLevelService(SecurityLevelCalculator calculator,
      SecurityLevelStateRepository stateRepository,
      SecurityLevelEventRepository eventRepository,
      SecurityLevelProperties properties,
      Clock clock) {
    this.calculator = calculator;
    this.stateRepository = stateRepository;
    this.eventRepository = eventRepository;
    this.properties = properties;
    this.clock = clock;
  }

  public SecurityLevelState currentLevel(String tenantId, String userId) {
    if (!StringUtils.hasText(tenantId) || !StringUtils.hasText(userId)) {
      return calculator.defaultState();
    }
    String trimmedTenant = tenantId.trim();
    String trimmedUser = userId.trim();
    SecurityLevelStateEntity entity = stateRepository
        .findById(new SecurityLevelStateId(trimmedTenant, trimmedUser))
        .orElse(null);
    Instant now = clock.instant();
    SecurityLevelState current = toState(entity);
    boolean entityExpired = current == null || current.isExpired(now);
    SecurityLevelState refreshed = calculator.refreshIfExpired(current);
    if (entityExpired) {
      saveState(trimmedTenant, trimmedUser, refreshed);
    }
    return refreshed;
  }

  public SecurityLevelState registerAction(String tenantId, String userId, String actionType,
      String detail) {
    if (!StringUtils.hasText(tenantId) || !StringUtils.hasText(userId)) {
      throw new IllegalArgumentException("테넌트와 사용자 ID가 필요합니다.");
    }
    String resolvedAction = StringUtils.hasText(actionType) ? actionType.trim() : "UNKNOWN";
    String resolvedDetail = StringUtils.hasText(detail) ? detail.trim() : "";
    Instant now = clock.instant();
    String trimmedTenant = tenantId.trim();
    String trimmedUser = userId.trim();
    SecurityLevelState current = currentLevel(trimmedTenant, trimmedUser);
    UserActionEvent event = new UserActionEvent(trimmedTenant, trimmedUser, resolvedAction,
        resolvedDetail, now);

    SecurityLevelEventEntity eventEntity = new SecurityLevelEventEntity();
    eventEntity.setTenantId(trimmedTenant);
    eventEntity.setUserId(trimmedUser);
    eventEntity.setActionType(resolvedAction);
    eventEntity.setActionDetail(resolvedDetail);
    eventEntity.setOccurredAt(now);
    eventRepository.save(eventEntity);

    SecurityLevelState next = calculator.applyEvent(current, event);
    saveState(trimmedTenant, trimmedUser, next);
    pruneOldEvents(trimmedTenant, trimmedUser);
    return next;
  }

  public List<UserActionEvent> recentActions(String tenantId, String userId) {
    if (!StringUtils.hasText(tenantId) || !StringUtils.hasText(userId)) {
      return List.of();
    }
    return eventRepository.findByTenantIdAndUserIdOrderByOccurredAtDesc(tenantId.trim(),
            userId.trim(), PageRequest.of(0, properties.getRetentionEvents())).stream()
        .map(entity -> new UserActionEvent(
            entity.getTenantId(),
            entity.getUserId(),
            entity.getActionType(),
            entity.getActionDetail(),
            entity.getOccurredAt()
        ))
        .toList();
  }

  public SecurityLevel resolveSecurityLevel(String tenantId, String userId) {
    return currentLevel(tenantId, userId).level();
  }

  @Scheduled(fixedDelayString = "${security.level.cleanup-interval:PT5M}")
  @Transactional
  public void cleanupExpiredData() {
    Instant now = clock.instant();
    stateRepository.deleteExpired(now);
    Instant eventCutoff = now.minus(properties.getRetentionWindow());
    eventRepository.deleteOlderThan(eventCutoff);
  }

  private void saveState(String tenantId, String userId, SecurityLevelState state) {
    SecurityLevelStateEntity entity = new SecurityLevelStateEntity();
    entity.setTenantId(tenantId);
    entity.setUserId(userId);
    entity.setLevel(state.level());
    entity.setExpiresAt(state.expiresAt());
    entity.setScore(state.score());
    entity.setUpdatedAt(Instant.now());
    stateRepository.save(entity);
  }

  private SecurityLevelState toState(SecurityLevelStateEntity entity) {
    if (entity == null) {
      return null;
    }
    return new SecurityLevelState(entity.getLevel(), entity.getExpiresAt(), entity.getScore());
  }

  private void pruneOldEvents(String tenantId, String userId) {
    List<SecurityLevelEventEntity> events =
        eventRepository.findByTenantIdAndUserIdOrderByOccurredAtDesc(tenantId, userId,
            PageRequest.of(0, properties.getRetentionEvents()));
    if (events.size() == properties.getRetentionEvents()) {
      Instant cutoff = events.get(events.size() - 1).getOccurredAt();
      eventRepository.deleteOlderThanForUser(tenantId, userId, cutoff);
    }
  }
}
