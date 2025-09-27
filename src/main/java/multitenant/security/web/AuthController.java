package multitenant.security.web;

import jakarta.servlet.http.HttpSession;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;
import multitenant.security.security.TenantUserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthController {

  @GetMapping("/login")
  public String login() {
    return "login";
  }

  @GetMapping("/")
  public String home(Model model, HttpSession session) {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    Object principal = authentication.getPrincipal();
    if (principal instanceof TenantUserDetails details) {
      model.addAttribute("username", details.getUsername());
      model.addAttribute("tenantId", details.getTenantId());
      model.addAttribute("groups", details.getGroups());
      model.addAttribute("countryCode", details.getCountryCode());
    }

    Map<String, Object> sessionMap = new LinkedHashMap<>();
    session.getAttributeNames().asIterator().forEachRemaining(name ->
        sessionMap.put(name, session.getAttribute(name))
    );
    model.addAttribute("sessionAttributes", sessionMap);
    return "home";
  }
}
