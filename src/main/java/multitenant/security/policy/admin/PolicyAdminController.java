package multitenant.security.policy.admin;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.stream.Collectors;
import multitenant.security.policy.domain.PolicyConditionType;
import multitenant.security.policy.domain.PolicyEffect;
import multitenant.security.policy.filter.SessionPolicyFilter;
import multitenant.security.securitylevel.SecurityLevelState;
import multitenant.security.securitylevel.service.SecurityLevelService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/admin/policies")
public class PolicyAdminController {

  private final PolicyAdminService policyAdminService;
  private final SecurityLevelService securityLevelService;

  public PolicyAdminController(PolicyAdminService policyAdminService,
      SecurityLevelService securityLevelService) {
    this.policyAdminService = policyAdminService;
    this.securityLevelService = securityLevelService;
  }

  @GetMapping
  public String viewPolicies(Model model, HttpServletRequest request) {
    prepareBaseModel(model, request);
    return "admin/policies";
  }

  @PostMapping
  public String createPolicy(@ModelAttribute PolicyCreationForm policyForm,
      RedirectAttributes redirectAttributes) {
    try {
      policyAdminService.createPolicy(policyForm);
      redirectAttributes.addFlashAttribute("successMessage", "정책이 생성되었습니다.");
    } catch (IllegalArgumentException ex) {
      redirectAttributes.addFlashAttribute("errorMessage", ex.getMessage());
      redirectAttributes.addFlashAttribute("policyForm", policyForm);
    }
    return "redirect:/admin/policies";
  }

  @PostMapping("/{policyId}/toggle")
  public String togglePolicy(@PathVariable Long policyId, RedirectAttributes redirectAttributes) {
    try {
      policyAdminService.togglePolicy(policyId);
      redirectAttributes.addFlashAttribute("successMessage", "정책 활성 상태가 변경되었습니다.");
    } catch (IllegalArgumentException ex) {
      redirectAttributes.addFlashAttribute("errorMessage", ex.getMessage());
    }
    return "redirect:/admin/policies";
  }

  @PostMapping("/{policyId}/delete")
  public String deletePolicy(@PathVariable Long policyId, RedirectAttributes redirectAttributes) {
    try {
      policyAdminService.deletePolicy(policyId);
      redirectAttributes.addFlashAttribute("successMessage", "정책이 삭제되었습니다.");
    } catch (IllegalArgumentException ex) {
      redirectAttributes.addFlashAttribute("errorMessage", ex.getMessage());
    }
    return "redirect:/admin/policies";
  }

  @PostMapping("/evaluate")
  public String evaluatePolicy(@ModelAttribute PolicyTestForm testForm,
      RedirectAttributes redirectAttributes, HttpServletRequest request) {
    try {
      PolicyTestOutcome outcome = policyAdminService.evaluatePolicy(testForm);
      redirectAttributes.addFlashAttribute("testOutcome", outcome);
      redirectAttributes.addFlashAttribute("testForm", testForm);
    } catch (IllegalArgumentException ex) {
      redirectAttributes.addFlashAttribute("errorMessage", ex.getMessage());
      redirectAttributes.addFlashAttribute("testForm", testForm);
    }
    HttpSession session = request.getSession(false);
    if (session != null) {
      storeLastFormValues(testForm, session);
    }
    return "redirect:/admin/policies";
  }

  @PostMapping("/session")
  public String seedSessionContext(@ModelAttribute PolicyTestForm sessionForm,
      HttpServletRequest request, RedirectAttributes redirectAttributes) {
    HttpSession session = request.getSession(true);
    if (StringUtils.hasText(sessionForm.getTenantId())) {
      session.setAttribute("tenantId", sessionForm.getTenantId().trim());
    }
    if (StringUtils.hasText(sessionForm.getUserId())) {
      session.setAttribute("userId", sessionForm.getUserId().trim());
    }
    session.setAttribute("groupIds", Arrays.stream(
            StringUtils.hasText(sessionForm.getGroupIds()) ? sessionForm.getGroupIds().split(",|\n")
                : new String[0])
        .map(String::trim)
        .filter(StringUtils::hasText)
        .collect(Collectors.toCollection(LinkedHashSet::new)));
    if (StringUtils.hasText(sessionForm.getCountryCode())) {
      session.setAttribute("countryCode", sessionForm.getCountryCode().trim());
    }
    if (StringUtils.hasText(sessionForm.getClientIp())) {
      session.setAttribute("clientIp", sessionForm.getClientIp().trim());
    }
    redirectAttributes.addFlashAttribute("successMessage", "세션 컨텍스트가 갱신되었습니다.");
    redirectAttributes.addFlashAttribute("testForm", sessionForm);
    return "redirect:/admin/policies";
  }

  @PostMapping("/security-level/events")
  public String registerSecurityEvent(@ModelAttribute SecurityLevelActionForm actionForm,
      RedirectAttributes redirectAttributes) {
    try {
      securityLevelService.registerAction(actionForm.getTenantId(), actionForm.getUserId(),
          actionForm.getActionType(), actionForm.getDetail());
      redirectAttributes.addFlashAttribute("successMessage", "행동 이벤트가 기록되었습니다.");
    } catch (IllegalArgumentException ex) {
      redirectAttributes.addFlashAttribute("errorMessage", ex.getMessage());
    }
    redirectAttributes.addFlashAttribute("securityActionForm", actionForm);
    return "redirect:/admin/policies";
  }

  private void prepareBaseModel(Model model, HttpServletRequest request) {
    if (!model.containsAttribute("policyForm")) {
      model.addAttribute("policyForm", new PolicyCreationForm());
    }
    if (!model.containsAttribute("testForm")) {
      PolicyTestForm form = new PolicyTestForm();
      HttpSession session = request.getSession(false);
      if (session != null) {
        form.setTenantId(attributeAsString(session.getAttribute("tenantId")));
        form.setUserId(attributeAsString(session.getAttribute("userId")));
        form.setGroupIds(joinCollection(session.getAttribute("groupIds")));
        form.setCountryCode(attributeAsString(session.getAttribute("countryCode")));
        form.setClientIp(attributeAsString(session.getAttribute("clientIp")));
        form.setDate(attributeAsString(session.getAttribute("lastTestDate")));
        form.setTime(attributeAsString(session.getAttribute("lastTestTime")));
        form.setZoneId(attributeAsString(session.getAttribute("lastTestZone")));
      }
      model.addAttribute("testForm", form);
    }
    PolicyTestForm form = (PolicyTestForm) model.asMap().get("testForm");
    if (!model.containsAttribute("securityActionForm")) {
      SecurityLevelActionForm actionForm = new SecurityLevelActionForm();
      if (form != null) {
        actionForm.setTenantId(form.getTenantId());
        actionForm.setUserId(form.getUserId());
      }
      model.addAttribute("securityActionForm", actionForm);
    }
    model.addAttribute("policies", policyAdminService.findAllPolicies());
    model.addAttribute("conditionTypes", PolicyConditionType.values());
    model.addAttribute("effects", PolicyEffect.values());
    model.addAttribute("zoneId", ZoneId.systemDefault().getId());
    enrichSessionAttributes(model, request.getSession(false));
    populateSecurityLevel(model, form);
  }

  private void enrichSessionAttributes(Model model, HttpSession session) {
    if (session == null) {
      model.addAttribute("sessionAttributes", Map.of());
      return;
    }
    Map<String, Object> attributes = new LinkedHashMap<>();
    attributes.put("tenantId", session.getAttribute("tenantId"));
    attributes.put("userId", session.getAttribute("userId"));
    attributes.put("groupIds", session.getAttribute("groupIds"));
    attributes.put("countryCode", session.getAttribute("countryCode"));
    attributes.put("clientIp", session.getAttribute("clientIp"));
    attributes.put(SessionPolicyFilter.SESSION_POLICY_ID_ATTR,
        session.getAttribute(SessionPolicyFilter.SESSION_POLICY_ID_ATTR));
    attributes.put(SessionPolicyFilter.SESSION_POLICY_EFFECT_ATTR,
        session.getAttribute(SessionPolicyFilter.SESSION_POLICY_EFFECT_ATTR));
    attributes.put(SessionPolicyFilter.SESSION_SECURITY_LEVEL_ATTR,
        session.getAttribute(SessionPolicyFilter.SESSION_SECURITY_LEVEL_ATTR));
    model.addAttribute("sessionAttributes", attributes);
  }

  private void storeLastFormValues(PolicyTestForm form, HttpSession session) {
    session.setAttribute("lastTestDate", form.getDate());
    session.setAttribute("lastTestTime", form.getTime());
    session.setAttribute("lastTestZone", form.getZoneId());
  }

  private String attributeAsString(Object value) {
    if (value == null) {
      return null;
    }
    if (value instanceof java.util.Collection<?> collection) {
      return collection.stream().map(Object::toString).collect(Collectors.joining(","));
    }
    return value.toString();
  }

  private String joinCollection(Object value) {
    if (value instanceof java.util.Collection<?> collection) {
      return collection.stream().map(Object::toString)
          .collect(Collectors.joining(","));
    }
    return attributeAsString(value);
  }

  private void populateSecurityLevel(Model model, PolicyTestForm testForm) {
    if (testForm == null || !StringUtils.hasText(testForm.getTenantId())
        || !StringUtils.hasText(testForm.getUserId())) {
      model.addAttribute("securityLevelState", null);
      model.addAttribute("securityEvents", java.util.List.of());
      return;
    }
    SecurityLevelState state = securityLevelService.currentLevel(testForm.getTenantId(),
        testForm.getUserId());
    model.addAttribute("securityLevelState", state);
    model.addAttribute("securityEvents",
        securityLevelService.recentActions(testForm.getTenantId(), testForm.getUserId()));
  }
}
