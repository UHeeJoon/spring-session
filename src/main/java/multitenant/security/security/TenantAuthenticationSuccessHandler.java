package multitenant.security.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.LinkedHashSet;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class TenantAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {
    HttpSession session = request.getSession(true);
    Object principal = authentication.getPrincipal();
    if (principal instanceof TenantUserDetails details) {
      session.setAttribute("tenantId", details.getTenantId());
      session.setAttribute("userId", details.getUsername());
      session.setAttribute("groupIds", new LinkedHashSet<>(details.getGroups()));
      session.setAttribute("countryCode", details.getCountryCode());
      session.setAttribute("clientIp", request.getRemoteAddr());
    }
    response.sendRedirect("/");
  }
}
