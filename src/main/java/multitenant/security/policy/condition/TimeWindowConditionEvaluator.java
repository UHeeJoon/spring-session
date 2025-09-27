package multitenant.security.policy.condition;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.DateTimeException;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import multitenant.security.policy.domain.PolicyConditionType;
import multitenant.security.policy.domain.SessionPolicy;
import multitenant.security.policy.service.PolicyEvaluationContext;
import org.springframework.stereotype.Component;

@Component
class TimeWindowConditionEvaluator implements PolicyConditionEvaluator {

  private final ObjectMapper objectMapper;

  TimeWindowConditionEvaluator(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  @Override
  public boolean supports(PolicyConditionType conditionType) {
    return conditionType == PolicyConditionType.TIME_WINDOW;
  }

  @Override
  public boolean matches(SessionPolicy policy, PolicyEvaluationContext context) {
    try {
      TimeWindowCondition condition =
          objectMapper.readValue(policy.getConditionValue(), TimeWindowCondition.class);
      if (condition.start() == null || condition.end() == null) {
        return false;
      }
      ZoneId zone = resolveZone(condition, context.requestDateTime());
      LocalTime start = LocalTime.parse(condition.start());
      LocalTime end = LocalTime.parse(condition.end());
      LocalTime requestTime = context.requestDateTime().withZoneSameInstant(zone).toLocalTime();
      if (start.equals(end)) {
        return true;
      }
      if (start.isBefore(end)) {
        return !requestTime.isBefore(start) && !requestTime.isAfter(end);
      }
      return !requestTime.isAfter(end) || !requestTime.isBefore(start);
    } catch (Exception ex) {
      return false;
    }
  }

  private ZoneId resolveZone(TimeWindowCondition condition, ZonedDateTime reference) {
    if (condition.zone() == null || condition.zone().isBlank()) {
      return reference.getZone();
    }
    try {
      return ZoneId.of(condition.zone());
    } catch (DateTimeException ex) {
      return reference.getZone();
    }
  }

  private record TimeWindowCondition(String start, String end, String zone) {
  }
}
