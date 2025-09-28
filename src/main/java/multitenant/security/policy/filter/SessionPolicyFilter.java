package multitenant.security.policy.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import multitenant.security.policy.service.PolicyEvaluationContext;
import multitenant.security.policy.service.PolicyEvaluationResult;
import multitenant.security.policy.service.SessionPolicyService;
import multitenant.security.sessionlimit.service.SessionLimitSettings;
import multitenant.security.sessionlimit.service.TenantSessionLimitService;
import multitenant.security.securitylevel.SecurityLevel;
import multitenant.security.securitylevel.service.SecurityLevelService;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class SessionPolicyFilter extends OncePerRequestFilter {

  public static final String SESSION_POLICY_ID_ATTR = "sessionPolicy:lastAppliedId";
  public static final String SESSION_POLICY_EFFECT_ATTR = "sessionPolicy:lastEffect";
  public static final String SESSION_SECURITY_LEVEL_ATTR = "sessionSecurity:level";
  private static final String REQUEST_ROTATED_ATTR =
      SessionPolicyFilter.class.getName() + ".rotated";

  private final SessionPolicyService sessionPolicyService;
  private final SecurityLevelService securityLevelService;
  private final TenantSessionLimitService tenantSessionLimitService;
  private final FindByIndexNameSessionRepository<? extends Session> sessionRepository;
  private final Clock clock;

  public SessionPolicyFilter(SessionPolicyService sessionPolicyService,
      SecurityLevelService securityLevelService,
      TenantSessionLimitService tenantSessionLimitService,
      FindByIndexNameSessionRepository<? extends Session> sessionRepository,
      Clock clock) {
    this.sessionPolicyService = sessionPolicyService;
    this.securityLevelService = securityLevelService;
    this.tenantSessionLimitService = tenantSessionLimitService;
    this.sessionRepository = sessionRepository;
    this.clock = clock;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    HttpSession session = request.getSession(false);
    if (session != null) {
      rotateSessionId(request, session);
      PolicyEvaluationContext context = buildContext(request, session);
      PolicyEvaluationResult result = sessionPolicyService.evaluate(context);
      session.setAttribute(SESSION_POLICY_ID_ATTR, result.policyId());
      session.setAttribute(SESSION_POLICY_EFFECT_ATTR, result.effect());
      applySecurityLevel(session, context);
      applySessionLimits(session, context);
      if (!result.allowed()) {
        throw new AccessDeniedException("Access blocked by session policy");
      }
    }
    filterChain.doFilter(request, response);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    String path = request.getServletPath();
    if (HttpMethod.OPTIONS.matches(request.getMethod())) {
      return true;
    }
    return path.startsWith("/login") || path.startsWith("/actuator") || path.startsWith("/error");
  }

  private PolicyEvaluationContext buildContext(HttpServletRequest request, HttpSession session) {
    String tenantId = firstNonBlank(
        attributeAsString(session.getAttribute("tenantId")),
        request.getHeader("X-Tenant-Id"));
    String userId = firstNonBlank(
        attributeAsString(session.getAttribute("userId")),
        request.getHeader("X-User-Id"));
    Set<String> groupIds = resolveGroups(session.getAttribute("groupIds"),
        request.getHeader("X-Group-Ids"));
    String clientIp = firstNonBlank(attributeAsString(session.getAttribute("clientIp")),
        resolveClientIp(request));
    String country = firstNonBlank(
        attributeAsString(session.getAttribute("countryCode")),
        request.getHeader("X-Location-Country"));
    if (country != null) {
      country = country.trim().toUpperCase(Locale.ROOT);
    }
    return new PolicyEvaluationContext(tenantId, userId, groupIds, clientIp, country,
        ZonedDateTime.now());
  }

  private void applySecurityLevel(HttpSession session, PolicyEvaluationContext context) {
    if (context.tenantId() == null || context.tenantId().isBlank()
        || context.userId() == null || context.userId().isBlank()) {
      session.setAttribute(SESSION_SECURITY_LEVEL_ATTR, SecurityLevel.LOW);
      return;
    }
    SecurityLevel level = securityLevelService.resolveSecurityLevel(context.tenantId(),
        context.userId());
    session.setAttribute(SESSION_SECURITY_LEVEL_ATTR, level);
    if (level == SecurityLevel.HIGH) {
      throw new AccessDeniedException("Access blocked due to high security risk level");
    }
  }

  private void applySessionLimits(HttpSession session, PolicyEvaluationContext context) {
    if (context.tenantId() == null || context.tenantId().isBlank()) {
      return;
    }
    String tenantId = context.tenantId().trim();
    SessionLimitSettings settings = tenantSessionLimitService.resolveForTenant(tenantId);

    if (settings.maxIdle().isZero()) {
      session.setMaxInactiveInterval(-1);
    } else if (settings.hasIdleLimit()) {
      long idleSeconds = Math.min(Integer.MAX_VALUE, Math.max(1, settings.maxIdle().getSeconds()));
      session.setMaxInactiveInterval((int) idleSeconds);
    }

    if (settings.hasDurationLimit()) {
      Instant created = Instant.ofEpochMilli(session.getCreationTime());
      Instant expiration = created.plus(settings.maxDuration());
      if (clock.instant().isAfter(expiration)) {
        session.invalidate();
        throw new AccessDeniedException("Session exceeded maximum lifetime");
      }
    }

    if (!settings.hasMaxSessionsLimit()) {
      return;
    }

    session.setAttribute(TenantSessionLimitService.SESSION_INDEX_KEY_ATTRIBUTE, tenantId);
    Map<String, ? extends Session> indexedSessions = sessionRepository
        .findByIndexNameAndIndexValue(TenantSessionLimitService.SESSION_INDEX_KEY_ATTRIBUTE,
            tenantId);

    if (indexedSessions == null) {
      return;
    }

    boolean currentRegistered = indexedSessions.containsKey(session.getId());
    int expectedSize = indexedSessions.size() + (currentRegistered ? 0 : 1);
    if (expectedSize <= settings.maxSessions()) {
      return;
    }

    int sessionsToRemove = expectedSize - settings.maxSessions();
    var orderedSessions = indexedSessions.entrySet().stream()
        .sorted(Comparator.comparing(entry -> entry.getValue().getLastAccessedTime()))
        .toList();
    for (var entry : orderedSessions) {
      String sessionId = entry.getKey();
      if (sessionId.equals(session.getId())) {
        continue;
      }
      sessionRepository.deleteById(sessionId);
      sessionsToRemove--;
      if (sessionsToRemove <= 0) {
        break;
      }
    }

    if (sessionsToRemove > 0) {
      session.invalidate();
      throw new AccessDeniedException("Maximum session count exceeded");
    }
  }

  private void rotateSessionId(HttpServletRequest request, HttpSession session) {
    if (request.getAttribute(REQUEST_ROTATED_ATTR) != null) {
      return;
    }
    request.setAttribute(REQUEST_ROTATED_ATTR, Boolean.TRUE);
    request.changeSessionId();
  }

  private String resolveClientIp(HttpServletRequest request) {
    String forwarded = request.getHeader("X-Forwarded-For");
    if (forwarded != null && !forwarded.isBlank()) {
      return forwarded.split(",")[0].trim();
    }
    return request.getRemoteAddr();
  }

  private Set<String> resolveGroups(Object attribute, String header) {
    Set<String> groups = new LinkedHashSet<>();
    if (attribute instanceof Collection<?> collection) {
      for (Object value : collection) {
        String text = attributeAsString(value);
        if (text != null && !text.isBlank()) {
          groups.add(text);
        }
      }
    } else {
      String text = attributeAsString(attribute);
      if (text != null && !text.isBlank()) {
        groups.add(text);
      }
    }
    if (header != null && !header.isBlank()) {
      groups.addAll(Arrays.stream(header.split(","))
          .map(String::trim)
          .filter(s -> !s.isBlank())
          .collect(Collectors.toCollection(LinkedHashSet::new)));
    }
    return groups;
  }

  private String attributeAsString(Object value) {
    return value == null ? null : value.toString();
  }

  private String firstNonBlank(String... values) {
    for (String value : values) {
      if (value != null && !value.isBlank()) {
        return value;
      }
    }
    return null;
  }
}
