package multitenant.security.policy.admin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import multitenant.security.policy.domain.PolicyConditionType;
import multitenant.security.policy.domain.PolicyEffect;
import multitenant.security.policy.domain.PolicyScopeType;
import multitenant.security.policy.domain.SessionPolicy;
import multitenant.security.policy.domain.SessionPolicyScope;
import multitenant.security.policy.repository.SessionPolicyRepository;
import multitenant.security.policy.service.PolicyEvaluationContext;
import multitenant.security.policy.service.PolicyEvaluationResult;
import multitenant.security.policy.service.SessionPolicyService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@Transactional
public class PolicyAdminService {

  private final SessionPolicyRepository sessionPolicyRepository;
  private final SessionPolicyService sessionPolicyService;
  private final ObjectMapper objectMapper;

  public PolicyAdminService(SessionPolicyRepository sessionPolicyRepository,
      SessionPolicyService sessionPolicyService, ObjectMapper objectMapper) {
    this.sessionPolicyRepository = sessionPolicyRepository;
    this.sessionPolicyService = sessionPolicyService;
    this.objectMapper = objectMapper;
  }

  public SessionPolicy createPolicy(PolicyCreationForm form) {
    validateCreationForm(form);
    SessionPolicy policy = new SessionPolicy();
    policy.setName(form.getName().trim());
    policy.setConditionType(form.getConditionType());
    policy.setConditionValue(buildConditionValue(form));
    policy.setEffect(form.getEffect());
    policy.setPriority(form.getPriority() == null ? 100 : form.getPriority());
    policy.setActive(form.isActive());

    policy.getScopes().clear();
    SessionPolicyScope tenantScope = new SessionPolicyScope();
    tenantScope.setScopeType(PolicyScopeType.TENANT);
    tenantScope.setScopeValue(form.getTenantId().trim());
    policy.addScope(tenantScope);

    Set<String> groupIds = parseTokenSet(form.getGroupIds());
    Set<String> excludedGroupIds = parseTokenSet(form.getExcludedGroupIds());
    ensureDisjoint(groupIds, excludedGroupIds, "그룹 ID");

    groupIds.forEach(groupId -> policy.addScope(buildScope(PolicyScopeType.GROUP, groupId, false)));
    excludedGroupIds
        .forEach(groupId -> policy.addScope(buildScope(PolicyScopeType.GROUP, groupId, true)));

    Set<String> userIds = parseTokenSet(form.getUserIds());
    Set<String> excludedUserIds = parseTokenSet(form.getExcludedUserIds());
    ensureDisjoint(userIds, excludedUserIds, "사용자 ID");

    userIds.forEach(userId -> policy.addScope(buildScope(PolicyScopeType.USER, userId, false)));
    excludedUserIds
        .forEach(userId -> policy.addScope(buildScope(PolicyScopeType.USER, userId, true)));

    return sessionPolicyRepository.save(policy);
  }

  public void togglePolicy(Long policyId) {
    SessionPolicy policy = sessionPolicyRepository.findById(policyId)
        .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 정책입니다."));
    policy.setActive(!policy.isActive());
  }

  public void deletePolicy(Long policyId) {
    SessionPolicy policy = sessionPolicyRepository.findById(policyId)
        .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 정책입니다."));
    sessionPolicyRepository.delete(policy);
  }

  @Transactional(readOnly = true)
  public List<PolicySummary> findAllPolicies() {
    return sessionPolicyRepository.findAllByOrderByPriorityDesc().stream()
        .map(this::toSummary)
        .sorted(Comparator.comparingInt(PolicySummary::priority).reversed()
            .thenComparingLong(PolicySummary::id))
        .toList();
  }

  @Transactional(readOnly = true)
  public PolicyTestOutcome evaluatePolicy(PolicyTestForm form) {
    PolicyEvaluationContext context = toEvaluationContext(form);
    PolicyEvaluationResult result = sessionPolicyService.evaluate(context);
    return new PolicyTestOutcome(context, result);
  }

  private void validateCreationForm(PolicyCreationForm form) {
    if (!StringUtils.hasText(form.getName())) {
      throw new IllegalArgumentException("정책 이름을 입력하세요.");
    }
    if (!StringUtils.hasText(form.getTenantId())) {
      throw new IllegalArgumentException("테넌트 ID를 입력하세요.");
    }
    if (form.getConditionType() == null) {
      throw new IllegalArgumentException("정책 조건 유형을 선택하세요.");
    }
    if (form.getEffect() == null) {
      throw new IllegalArgumentException("허용/차단 효과를 선택하세요.");
    }
  }

  private String buildConditionValue(PolicyCreationForm form) {
    try {
      return switch (form.getConditionType()) {
        case TIME_WINDOW -> objectMapper.writeValueAsString(buildTimeWindowPayload(form));
        case IP_RANGE -> objectMapper.writeValueAsString(buildIpRangePayload(form));
        case LOCATION -> objectMapper.writeValueAsString(buildLocationPayload(form));
      };
    } catch (JsonProcessingException ex) {
      throw new IllegalArgumentException("조건 값을 직렬화하는 중 오류가 발생했습니다.", ex);
    }
  }

  private Map<String, Object> buildTimeWindowPayload(PolicyCreationForm form) {
    if (!StringUtils.hasText(form.getTimeStart()) || !StringUtils.hasText(form.getTimeEnd())) {
      throw new IllegalArgumentException("시간대 정책은 시작/종료 시간을 모두 입력해야 합니다.");
    }
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("start", form.getTimeStart().trim());
    payload.put("end", form.getTimeEnd().trim());
    if (StringUtils.hasText(form.getTimeZoneId())) {
      payload.put("zone", form.getTimeZoneId().trim());
    }
    return payload;
  }

  private Map<String, Object> buildIpRangePayload(PolicyCreationForm form) {
    Set<String> cidrSet = parseTokenSet(form.getIpCidrs());
    if (cidrSet.isEmpty()) {
      throw new IllegalArgumentException("IP 대역 정책은 CIDR 값을 최소 1개 이상 입력해야 합니다.");
    }
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("cidr", new ArrayList<>(cidrSet));
    return payload;
  }

  private Map<String, Object> buildLocationPayload(PolicyCreationForm form) {
    Set<String> countries = parseTokenSet(form.getCountries());
    if (countries.isEmpty()) {
      throw new IllegalArgumentException("위치 기반 정책은 국가 코드를 최소 1개 이상 입력해야 합니다.");
    }
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("countries", new ArrayList<>(countries));
    return payload;
  }

  private Set<String> parseTokenSet(String value) {
    if (!StringUtils.hasText(value)) {
      return Set.of();
    }
    return Arrays.stream(value.split(",|\n"))
        .map(String::trim)
        .filter(StringUtils::hasText)
        .collect(Collectors.toCollection(LinkedHashSet::new));
  }

  private PolicySummary toSummary(SessionPolicy policy) {
    Map<PolicyScopeType, Map<Boolean, List<String>>> scopeMap = policy.getScopes().stream()
        .collect(Collectors.groupingBy(SessionPolicyScope::getScopeType,
            Collectors.groupingBy(SessionPolicyScope::isExcluded,
                Collectors.mapping(SessionPolicyScope::getScopeValue,
                    Collectors.collectingAndThen(
                        Collectors.toCollection(LinkedHashSet::new),
                        list -> list.stream().toList())))));
    List<String> tenantIncludes = scopeMap.getOrDefault(PolicyScopeType.TENANT, Map.of())
        .getOrDefault(false, List.of());
    List<String> tenantExcludes = scopeMap.getOrDefault(PolicyScopeType.TENANT, Map.of())
        .getOrDefault(true, List.of());
    List<String> groupIncludes = scopeMap.getOrDefault(PolicyScopeType.GROUP, Map.of())
        .getOrDefault(false, List.of());
    List<String> groupExcludes = scopeMap.getOrDefault(PolicyScopeType.GROUP, Map.of())
        .getOrDefault(true, List.of());
    List<String> userIncludes = scopeMap.getOrDefault(PolicyScopeType.USER, Map.of())
        .getOrDefault(false, List.of());
    List<String> userExcludes = scopeMap.getOrDefault(PolicyScopeType.USER, Map.of())
        .getOrDefault(true, List.of());

    return new PolicySummary(
        policy.getId(),
        policy.getName(),
        policy.getConditionType(),
        policy.getConditionValue(),
        policy.getEffect(),
        policy.getPriority(),
        policy.isActive(),
        tenantIncludes,
        tenantExcludes,
        groupIncludes,
        groupExcludes,
        userIncludes,
        userExcludes
    );
  }

  private PolicyEvaluationContext toEvaluationContext(PolicyTestForm form) {
    Set<String> groups = parseTokenSet(form.getGroupIds());
    ZonedDateTime requestDateTime = resolveDateTime(form);
    return new PolicyEvaluationContext(
        blankToNull(form.getTenantId()),
        blankToNull(form.getUserId()),
        groups,
        blankToNull(form.getClientIp()),
        blankToNull(form.getCountryCode()),
        requestDateTime
    );
  }

  private ZonedDateTime resolveDateTime(PolicyTestForm form) {
    ZoneId zone = resolveZone(form.getZoneId());
    LocalDate date = parseLocalDate(form.getDate());
    LocalTime time = parseLocalTime(form.getTime());
    if (date != null && time != null) {
      return ZonedDateTime.of(date, time, zone);
    }
    return ZonedDateTime.now(zone);
  }

  private ZoneId resolveZone(String zoneId) {
    if (StringUtils.hasText(zoneId)) {
      try {
        return ZoneId.of(zoneId.trim());
      } catch (Exception ignored) {
      }
    }
    return ZoneId.systemDefault();
  }

  private LocalDate parseLocalDate(String value) {
    if (!StringUtils.hasText(value)) {
      return null;
    }
    try {
      return LocalDate.parse(value.trim());
    } catch (Exception ex) {
      throw new IllegalArgumentException("날짜 형식이 올바르지 않습니다. (예: 2025-01-01)");
    }
  }

  private LocalTime parseLocalTime(String value) {
    if (!StringUtils.hasText(value)) {
      return null;
    }
    try {
      return LocalTime.parse(value.trim());
    } catch (Exception ex) {
      throw new IllegalArgumentException("시간 형식이 올바르지 않습니다. (예: 13:30)");
    }
  }

  private SessionPolicyScope buildScope(PolicyScopeType type, String value, boolean excluded) {
    SessionPolicyScope scope = new SessionPolicyScope();
    scope.setScopeType(type);
    scope.setScopeValue(value);
    scope.setExcluded(excluded);
    return scope;
  }

  private void ensureDisjoint(Set<String> includes, Set<String> excludes, String label) {
    if (includes.isEmpty() || excludes.isEmpty()) {
      return;
    }
    Set<String> intersection = includes.stream()
        .filter(excludes::contains)
        .collect(Collectors.toSet());
    if (!intersection.isEmpty()) {
      throw new IllegalArgumentException(label + " 제외 대상은 포함 대상과 겹칠 수 없습니다.");
    }
  }

  private String blankToNull(String value) {
    return StringUtils.hasText(value) ? value.trim() : null;
  }
}
