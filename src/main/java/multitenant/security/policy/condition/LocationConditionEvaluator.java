package multitenant.security.policy.condition;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import multitenant.security.policy.domain.PolicyConditionType;
import multitenant.security.policy.domain.SessionPolicy;
import multitenant.security.policy.service.PolicyEvaluationContext;
import org.springframework.stereotype.Component;

@Component
class LocationConditionEvaluator implements PolicyConditionEvaluator {

  private final ObjectMapper objectMapper;

  LocationConditionEvaluator(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  @Override
  public boolean supports(PolicyConditionType conditionType) {
    return conditionType == PolicyConditionType.LOCATION;
  }

  @Override
  public boolean matches(SessionPolicy policy, PolicyEvaluationContext context) {
    if (context.countryCode() == null || context.countryCode().isBlank()) {
      return false;
    }
    try {
      LocationCondition condition =
          objectMapper.readValue(policy.getConditionValue(), LocationCondition.class);
      List<String> countries =
          condition.countries() == null ? Collections.emptyList() : condition.countries();
      if (countries.isEmpty()) {
        return false;
      }
      String normalized = normalize(context.countryCode());
      for (String country : countries) {
        if (country != null && normalize(country).equals(normalized)) {
          return true;
        }
      }
      return false;
    } catch (Exception ex) {
      return false;
    }
  }

  private String normalize(String country) {
    return country.trim().toUpperCase(Locale.ROOT);
  }

  private record LocationCondition(List<String> countries) {
  }
}
