package multitenant.security.policy.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import multitenant.security.policy.service.PolicyEvaluationContext;
import multitenant.security.policy.service.PolicyEvaluationResult;
import multitenant.security.policy.service.SessionPolicyService;
import multitenant.security.securitylevel.SecurityLevel;
import multitenant.security.securitylevel.service.SecurityLevelService;
import multitenant.security.sessionlimit.service.SessionLimitSettings;
import multitenant.security.sessionlimit.service.TenantSessionLimitService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.MapSession;
import org.springframework.session.Session;

class SessionPolicyFilterTests {

  private SessionPolicyService sessionPolicyService;
  private SecurityLevelService securityLevelService;
  private TenantSessionLimitService tenantSessionLimitService;
  private FindByIndexNameSessionRepository<? extends Session> sessionRepository;
  private Clock clock;
  private SessionPolicyFilter filter;

  @BeforeEach
  void setUp() {
    sessionPolicyService = Mockito.mock(SessionPolicyService.class);
    securityLevelService = Mockito.mock(SecurityLevelService.class);
    tenantSessionLimitService = Mockito.mock(TenantSessionLimitService.class);
    sessionRepository = Mockito.mock(FindByIndexNameSessionRepository.class);
    clock = Clock.fixed(Instant.parse("2025-01-01T00:00:00Z"), ZoneOffset.UTC);
    filter = new SessionPolicyFilter(sessionPolicyService, securityLevelService,
        tenantSessionLimitService, sessionRepository, clock);

    given(sessionPolicyService.evaluate(any(PolicyEvaluationContext.class)))
        .willReturn(PolicyEvaluationResult.allow(null));
    given(securityLevelService.resolveSecurityLevel(anyString(), anyString()))
        .willReturn(SecurityLevel.LOW);
  }

  @Test
  void appliesIdleTimeoutFromTenantSettings() throws Exception {
    SessionLimitSettings settings = new SessionLimitSettings(0, Duration.ofMinutes(5), Duration.ZERO);
    given(tenantSessionLimitService.resolveForTenant("tenant1")).willReturn(settings);
    given(sessionRepository.findByIndexNameAndIndexValue(anyString(), anyString()))
        .willReturn(Map.of());

    MockHttpSession session = new MockHttpSession();
    String originalId = session.getId();
    session.setAttribute("tenantId", "tenant1");
    session.setAttribute("userId", "alice");

    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setSession(session);
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = new MockFilterChain();

    filter.doFilter(request, response, chain);

    assertThat(session.getMaxInactiveInterval()).isEqualTo(300);
    assertThat(session.getId()).isNotEqualTo(originalId);
    verify(sessionRepository, never()).findByIndexNameAndIndexValue(anyString(), anyString());
  }

  @Test
  void exceedsAbsoluteDurationInvalidatesSession() {
    SessionLimitSettings settings = new SessionLimitSettings(0, Duration.ofMinutes(30),
        Duration.ofMinutes(10));
    given(tenantSessionLimitService.resolveForTenant("tenant1")).willReturn(settings);
    given(sessionRepository.findByIndexNameAndIndexValue(anyString(), anyString()))
        .willReturn(Map.of());

    MockHttpSession session = new MutableCreationTimeSession(
        Instant.parse("2024-12-31T23:30:00Z").toEpochMilli());
    session.setAttribute("tenantId", "tenant1");
    session.setAttribute("userId", "alice");

    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setSession(session);
    MockHttpServletResponse response = new MockHttpServletResponse();

    assertThatThrownBy(() -> filter.doFilter(request, response, new MockFilterChain()))
        .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
  }

  @Test
  void zeroIdleTimeoutDisablesExpiration() throws Exception {
    SessionLimitSettings settings = new SessionLimitSettings(0, Duration.ZERO, Duration.ZERO);
    given(tenantSessionLimitService.resolveForTenant("tenant1")).willReturn(settings);
    given(sessionRepository.findByIndexNameAndIndexValue(anyString(), anyString()))
        .willReturn(Map.of());

    MockHttpSession session = new MockHttpSession();
    String originalId = session.getId();
    session.setAttribute("tenantId", "tenant1");
    session.setAttribute("userId", "alice");

    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setSession(session);
    MockHttpServletResponse response = new MockHttpServletResponse();

    filter.doFilter(request, response, new MockFilterChain());

    assertThat(session.getMaxInactiveInterval()).isEqualTo(-1);
    assertThat(session.getId()).isNotEqualTo(originalId);
  }

  @Test
  void enforcesMaxSessionsByRemovingOldOnes() throws Exception {
    SessionLimitSettings settings = new SessionLimitSettings(1, Duration.ofMinutes(30),
        Duration.ZERO);
    given(tenantSessionLimitService.resolveForTenant("tenant1")).willReturn(settings);

    MapSession olderSession = new MapSession("old-1");
    olderSession.setLastAccessedTime(clock.instant().minusSeconds(600));
    MapSession newerSession = new MapSession("old-2");
    newerSession.setLastAccessedTime(clock.instant().minusSeconds(60));

    given(sessionRepository.findByIndexNameAndIndexValue(
        TenantSessionLimitService.SESSION_INDEX_KEY_ATTRIBUTE, "tenant1"))
        .willReturn(Map.of(
            olderSession.getId(), olderSession,
            newerSession.getId(), newerSession
        ));

    MockHttpSession session = new MockHttpSession();
    String originalId = session.getId();
    session.setAttribute("tenantId", "tenant1");
    session.setAttribute("userId", "alice");

    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setSession(session);
    MockHttpServletResponse response = new MockHttpServletResponse();

    filter.doFilter(request, response, new MockFilterChain());

    assertThat(session.getAttribute(TenantSessionLimitService.SESSION_INDEX_KEY_ATTRIBUTE))
        .isEqualTo("tenant1");
    verify(sessionRepository).deleteById("old-1");
    verify(sessionRepository).deleteById("old-2");
    verify(sessionRepository, never()).deleteById(session.getId());
    assertThat(session.getId()).isNotEqualTo(originalId);
  }

  private static class MutableCreationTimeSession extends MockHttpSession {

    private final long creationTime;

    private MutableCreationTimeSession(long creationTime) {
      this.creationTime = creationTime;
    }

    @Override
    public long getCreationTime() {
      return creationTime;
    }
  }
}
