package multitenant.security.policy;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Set;
import multitenant.security.policy.domain.PolicyEffect;
import multitenant.security.policy.domain.PolicyScopeType;
import multitenant.security.policy.domain.SessionPolicy;
import multitenant.security.policy.domain.SessionPolicyScope;
import multitenant.security.policy.service.PolicyEvaluationContext;
import multitenant.security.policy.service.PolicyEvaluationResult;
import multitenant.security.policy.service.SessionPolicyService;
import multitenant.security.policy.repository.SessionPolicyRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
class SessionPolicyServiceTests {

  @Autowired
  private SessionPolicyService sessionPolicyService;

  @Autowired
  private SessionPolicyRepository sessionPolicyRepository;

  @BeforeEach
  void setUpPolicies() {
    sessionPolicyRepository.deleteAll();

    SessionPolicy denyCountry = createPolicy("tenant1", PolicyEffect.DENY,
        multitenant.security.policy.domain.PolicyConditionType.LOCATION,
        "{\"countries\":[\"CN\",\"RU\"]}", 130,
        scopes(tenant("tenant1")));

    SessionPolicy allowBusinessHours = createPolicy("tenant1", PolicyEffect.ALLOW,
        multitenant.security.policy.domain.PolicyConditionType.TIME_WINDOW,
        "{\"start\":\"06:00\",\"end\":\"20:00\",\"zone\":\"Asia/Seoul\"}", 90,
        scopes(tenant("tenant1")));

    SessionPolicy allowEngineeringIp = createPolicy("tenant1", PolicyEffect.ALLOW,
        multitenant.security.policy.domain.PolicyConditionType.IP_RANGE,
        "{\"cidr\":[\"10.0.0.0/8\",\"192.168.0.0/16\"]}", 110,
        scopes(tenant("tenant1"), group("engineering")));

    SessionPolicy allowTenantTwoBusiness = createPolicy("tenant2", PolicyEffect.ALLOW,
        multitenant.security.policy.domain.PolicyConditionType.TIME_WINDOW,
        "{\"start\":\"08:00\",\"end\":\"18:00\",\"zone\":\"UTC\"}", 90,
        scopes(tenant("tenant2")));

    SessionPolicy denyTenantTwoUser = createPolicy("tenant2", PolicyEffect.DENY,
        multitenant.security.policy.domain.PolicyConditionType.LOCATION,
        "{\"countries\":[\"KR\"]}", 140,
        scopes(tenant("tenant2"), user("blacklist-user")));

    sessionPolicyRepository.saveAll(
        List.of(denyCountry, allowBusinessHours, allowEngineeringIp, allowTenantTwoBusiness,
            denyTenantTwoUser));
  }

  @Test
  void deniesRequestWhenCountryIsBlocked() {
    PolicyEvaluationContext context = new PolicyEvaluationContext(
        "tenant1",
        "alice",
        Set.of("engineering"),
        "10.0.0.10",
        "CN",
        ZonedDateTime.of(2024, 1, 1, 10, 0, 0, 0, ZoneId.of("Asia/Seoul"))
    );

    PolicyEvaluationResult result = sessionPolicyService.evaluate(context);

    assertThat(sessionPolicyRepository.findAll()).isNotEmpty();
    assertThat(result.allowed()).isFalse();
    assertThat(result.effect()).isEqualTo(PolicyEffect.DENY);
  }

  @Test
  void allowsEngineeringTeamFromTrustedIpDuringBusinessHours() {
    PolicyEvaluationContext context = new PolicyEvaluationContext(
        "tenant1",
        "alice",
        Set.of("engineering"),
        "10.0.0.15",
        "KR",
        ZonedDateTime.of(2024, 1, 2, 11, 0, 0, 0, ZoneId.of("Asia/Seoul"))
    );

    PolicyEvaluationResult result = sessionPolicyService.evaluate(context);

    assertThat(result.allowed()).isTrue();
    assertThat(result.policyId()).isNotNull();
    assertThat(result.effect()).isEqualTo(PolicyEffect.ALLOW);
  }

  @Test
  void deniesBlacklistedUserForTenantTwo() {
    PolicyEvaluationContext context = new PolicyEvaluationContext(
        "tenant2",
        "blacklist-user",
        Set.of(),
        "203.0.113.5",
        "KR",
        ZonedDateTime.of(2024, 1, 3, 9, 0, 0, 0, ZoneId.of("UTC"))
    );

    PolicyEvaluationResult result = sessionPolicyService.evaluate(context);

    assertThat(result.allowed()).isFalse();
    assertThat(result.effect()).isEqualTo(PolicyEffect.DENY);
  }

  @Test
  void defaultsToAllowWhenNoPolicyMatches() {
    PolicyEvaluationContext context = new PolicyEvaluationContext(
        "tenant2",
        "bob",
        Set.of("sales"),
        "198.51.100.12",
        "US",
        ZonedDateTime.of(2024, 1, 4, 12, 0, 0, 0, ZoneId.of("UTC"))
    );

    PolicyEvaluationResult result = sessionPolicyService.evaluate(context);

    assertThat(result.allowed()).isTrue();
    assertThat(result.policyId()).isNotNull();
    assertThat(result.effect()).isEqualTo(PolicyEffect.ALLOW);
  }

  private SessionPolicy createPolicy(String tenantId, PolicyEffect effect,
      multitenant.security.policy.domain.PolicyConditionType conditionType,
      String conditionValue, int priority, Set<SessionPolicyScope> scopes) {
    SessionPolicy policy = new SessionPolicy();
    policy.setName(tenantId + " policy " + conditionType.name());
    policy.setEffect(effect);
    policy.setConditionType(conditionType);
    policy.setConditionValue(conditionValue);
    policy.setPriority(priority);
    policy.setActive(true);
    scopes.forEach(policy::addScope);
    return policy;
  }

  private Set<SessionPolicyScope> scopes(SessionPolicyScope... scopes) {
    return Set.of(scopes);
  }

  private SessionPolicyScope tenant(String tenantId) {
    SessionPolicyScope scope = new SessionPolicyScope();
    scope.setScopeType(PolicyScopeType.TENANT);
    scope.setScopeValue(tenantId);
    return scope;
  }

  private SessionPolicyScope group(String groupId) {
    SessionPolicyScope scope = new SessionPolicyScope();
    scope.setScopeType(PolicyScopeType.GROUP);
    scope.setScopeValue(groupId);
    return scope;
  }

  private SessionPolicyScope user(String userId) {
    SessionPolicyScope scope = new SessionPolicyScope();
    scope.setScopeType(PolicyScopeType.USER);
    scope.setScopeValue(userId);
    return scope;
  }
}
