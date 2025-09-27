package multitenant.security.policy.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import multitenant.security.policy.domain.PolicyConditionType;
import multitenant.security.policy.domain.PolicyEffect;
import multitenant.security.policy.domain.SessionPolicy;
import multitenant.security.policy.repository.SessionPolicyRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class PolicyAdminServiceTests {

  @Autowired
  private PolicyAdminService policyAdminService;

  @Autowired
  private SessionPolicyRepository sessionPolicyRepository;

  @BeforeEach
  void seedPolicies() {
    sessionPolicyRepository.deleteAll();
    PolicyCreationForm base = new PolicyCreationForm();
    base.setName("tenant1 base policy");
    base.setTenantId("tenant1");
    base.setConditionType(PolicyConditionType.TIME_WINDOW);
    base.setEffect(PolicyEffect.ALLOW);
    base.setTimeStart("06:00");
    base.setTimeEnd("20:00");
    base.setTimeZoneId("Asia/Seoul");
    policyAdminService.createPolicy(base);
  }

  @Test
  void createsNewPolicyForTenant() {
    PolicyCreationForm form = new PolicyCreationForm();
    form.setName("tenant3 business hours");
    form.setTenantId("tenant3");
    form.setConditionType(PolicyConditionType.TIME_WINDOW);
    form.setEffect(PolicyEffect.ALLOW);
    form.setTimeStart("09:00");
    form.setTimeEnd("18:00");
    form.setTimeZoneId("Asia/Seoul");
    form.setGroupIds("sales");

    SessionPolicy policy = policyAdminService.createPolicy(form);

    assertThat(policy.getId()).isNotNull();
    assertThat(policy.getScopes()).hasSizeGreaterThanOrEqualTo(1);
    List<SessionPolicy> tenantPolicies =
        sessionPolicyRepository.findAllByOrderByPriorityDesc().stream()
            .filter(p -> p.getScopes().stream()
                .anyMatch(scope -> "tenant3".equals(scope.getScopeValue())))
            .toList();
    assertThat(tenantPolicies).isNotEmpty();
  }

  @Test
  void rejectsWhenIncludeAndExcludeGroupsOverlap() {
    PolicyCreationForm form = new PolicyCreationForm();
    form.setName("overlap policy");
    form.setTenantId("tenant4");
    form.setConditionType(PolicyConditionType.TIME_WINDOW);
    form.setEffect(PolicyEffect.ALLOW);
    form.setTimeStart("09:00");
    form.setTimeEnd("18:00");
    form.setTimeZoneId("Asia/Seoul");
    form.setGroupIds("engineering");
    form.setExcludedGroupIds("engineering");

    assertThatThrownBy(() -> policyAdminService.createPolicy(form))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("겹칠 수 없습니다");
  }

  @Test
  void togglesPolicyActiveFlag() {
    PolicyCreationForm form = new PolicyCreationForm();
    form.setName("toggle policy");
    form.setTenantId("tenant1");
    form.setConditionType(PolicyConditionType.TIME_WINDOW);
    form.setEffect(PolicyEffect.ALLOW);
    form.setTimeStart("08:00");
    form.setTimeEnd("18:00");
    form.setTimeZoneId("Asia/Seoul");
    SessionPolicy policy = policyAdminService.createPolicy(form);

    boolean initial = policy.isActive();
    policyAdminService.togglePolicy(policy.getId());

    SessionPolicy reloaded = sessionPolicyRepository.findById(policy.getId()).orElseThrow();
    assertThat(reloaded.isActive()).isEqualTo(!initial);
  }

  @Test
  void deletesPolicy() {
    PolicyCreationForm form = new PolicyCreationForm();
    form.setName("delete target");
    form.setTenantId("tenant1");
    form.setConditionType(PolicyConditionType.TIME_WINDOW);
    form.setEffect(PolicyEffect.ALLOW);
    form.setTimeStart("07:00");
    form.setTimeEnd("22:00");
    form.setTimeZoneId("Asia/Seoul");
    SessionPolicy policy = policyAdminService.createPolicy(form);
    Long id = policy.getId();
    policyAdminService.deletePolicy(id);

    assertThat(sessionPolicyRepository.findById(id)).isEmpty();
  }
}
