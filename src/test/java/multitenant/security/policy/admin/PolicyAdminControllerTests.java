package multitenant.security.policy.admin;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.util.List;
import multitenant.security.policy.domain.PolicyConditionType;
import multitenant.security.policy.domain.PolicyEffect;
import multitenant.security.policy.service.PolicyEvaluationResult;
import multitenant.security.securitylevel.SecurityLevel;
import multitenant.security.securitylevel.SecurityLevelState;
import multitenant.security.securitylevel.service.SecurityLevelService;
import multitenant.security.sessionlimit.domain.TenantSessionLimit;
import multitenant.security.sessionlimit.service.TenantSessionLimitService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(controllers = PolicyAdminController.class)
@WithMockUser
class PolicyAdminControllerTests {

  @Autowired
  private MockMvc mockMvc;

  @MockitoBean
  private PolicyAdminService policyAdminService;

  @MockitoBean
  private SecurityLevelService securityLevelService;

  @MockitoBean
  private multitenant.security.policy.service.SessionPolicyService sessionPolicyService;

  @MockitoBean
  private TenantSessionLimitService tenantSessionLimitService;

  private List<PolicySummary> samplePolicies;

  @BeforeEach
  void setUp() {
    samplePolicies = List.of(
        new PolicySummary(1L, "allow business", PolicyConditionType.TIME_WINDOW,
            "{\"start\":\"09:00\",\"end\":\"18:00\"}", PolicyEffect.ALLOW, 100, true,
            List.of("tenant1"), List.of(), List.of("engineering"), List.of(), List.of(), List.of())
    );

    given(policyAdminService.findAllPolicies()).willReturn(samplePolicies);
    given(securityLevelService.currentLevel(any(), any()))
        .willReturn(new SecurityLevelState(SecurityLevel.LOW, java.time.Instant.now(), 0));
    given(securityLevelService.recentActions(any(), any())).willReturn(List.of());
    given(policyAdminService.createPolicy(any(PolicyCreationForm.class)))
        .willReturn(new multitenant.security.policy.domain.SessionPolicy());
    given(sessionPolicyService.evaluate(any())).willReturn(PolicyEvaluationResult.allow(null));
    given(tenantSessionLimitService.findAll()).willReturn(List.of(
        new TenantSessionLimit("tenant1", 2, 600, 3600)
    ));
  }

  @Test
  void viewPoliciesShowsExistingData() throws Exception {
    mockMvc.perform(get("/admin/policies"))
        .andExpect(status().isOk())
        .andExpect(view().name("admin/policies"))
        .andExpect(model().attributeExists("policies"))
        .andExpect(model().attributeExists("policyForm"))
        .andExpect(model().attributeExists("testForm"));
  }

  @Test
  void createPolicyRedirectsWithSuccess() throws Exception {
    given(policyAdminService.createPolicy(any(PolicyCreationForm.class)))
        .willReturn(new multitenant.security.policy.domain.SessionPolicy());

    mockMvc.perform(post("/admin/policies")
            .param("name", "test policy")
            .param("tenantId", "tenant1")
            .param("conditionType", "TIME_WINDOW")
            .param("effect", "ALLOW")
            .param("timeStart", "09:00")
            .param("timeEnd", "18:00")
            .with(SecurityMockMvcRequestPostProcessors.csrf()))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/admin/policies"))
        .andExpect(flash().attribute("successMessage", containsString("생성")));

    verify(policyAdminService).createPolicy(any(PolicyCreationForm.class));
  }

  @Test
  void registerSecurityEventUsesService() throws Exception {
    mockMvc.perform(post("/admin/policies/security-level/events")
            .param("tenantId", "tenantX")
            .param("userId", "userY")
            .param("actionType", "LOGIN_FAILURE")
            .with(SecurityMockMvcRequestPostProcessors.csrf()))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/admin/policies"));

    verify(securityLevelService).registerAction(eq("tenantX"), eq("userY"), eq("LOGIN_FAILURE"),
        org.mockito.ArgumentMatchers.isNull());
  }

  @Test
  void saveSessionLimitInvokesService() throws Exception {
    mockMvc.perform(post("/admin/policies/limits")
            .param("tenantId", "tenantZ")
            .param("maxSessions", "2")
            .param("maxIdleSeconds", "900")
            .param("maxDurationSeconds", "3600")
            .with(SecurityMockMvcRequestPostProcessors.csrf()))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/admin/policies"));

    verify(tenantSessionLimitService).upsert("tenantZ", 2, 900, 3600);
  }
}
