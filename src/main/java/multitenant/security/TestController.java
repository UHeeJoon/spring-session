package multitenant.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

  @GetMapping("/session/mock")
  public String index(
      @RequestParam(defaultValue = "tenant1") String tenant,
      @RequestParam(defaultValue = "alice") String user,
      @RequestParam(required = false, name = "groups") String groupParam,
      @RequestParam(defaultValue = "KR") String country,
      HttpServletRequest request,
      HttpSession httpSession) {

    httpSession.setAttribute("tenantId", tenant);
    httpSession.setAttribute("userId", user);
    httpSession.setAttribute("countryCode", country);
    httpSession.setAttribute("groupIds", toGroupSet(groupParam));
    httpSession.setAttribute("clientIp", request.getRemoteAddr());
    return "session context initialized";
  }

  private Set<String> toGroupSet(String groupParam) {
    if (groupParam == null || groupParam.isBlank()) {
      return Set.of();
    }
    return Arrays.stream(groupParam.split(","))
        .map(String::trim)
        .filter(token -> !token.isBlank())
        .collect(Collectors.toCollection(LinkedHashSet::new));
  }

}
