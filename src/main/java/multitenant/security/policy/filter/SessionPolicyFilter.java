package multitenant.security.policy.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import multitenant.security.policy.service.PolicyEvaluationContext;
import multitenant.security.policy.service.PolicyEvaluationResult;
import multitenant.security.policy.service.SessionPolicyService;
import multitenant.security.securitylevel.SecurityLevel;
import multitenant.security.securitylevel.service.SecurityLevelService;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class SessionPolicyFilter extends OncePerRequestFilter {

  public static final String SESSION_POLICY_ID_ATTR = "sessionPolicy:lastAppliedId";
  public static final String SESSION_POLICY_EFFECT_ATTR = "sessionPolicy:lastEffect";
  public static final String SESSION_SECURITY_LEVEL_ATTR = "sessionSecurity:level";

  private final SessionPolicyService sessionPolicyService;
  private final SecurityLevelService securityLevelService;

  public SessionPolicyFilter(SessionPolicyService sessionPolicyService,
      SecurityLevelService securityLevelService) {
    this.sessionPolicyService = sessionPolicyService;
    this.securityLevelService = securityLevelService;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    HttpSession session = request.getSession(false);
    if (session != null) {
      PolicyEvaluationContext context = buildContext(request, session);
      PolicyEvaluationResult result = sessionPolicyService.evaluate(context);
      session.setAttribute(SESSION_POLICY_ID_ATTR, result.policyId());
      session.setAttribute(SESSION_POLICY_EFFECT_ATTR, result.effect());
      applySecurityLevel(session, context);
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
