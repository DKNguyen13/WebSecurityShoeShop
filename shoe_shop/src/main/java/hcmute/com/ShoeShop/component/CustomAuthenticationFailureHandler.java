package hcmute.com.ShoeShop.component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Autowired
    private LoginAttemptService loginAttemptService;

    private static final Logger logger = LoggerFactory.getLogger("userLogger");

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String email = request.getParameter("username"); // hoặc "email" tùy thuộc vào tên field trong form login
        loginAttemptService.loginFailed(email);

        String ipAddress = getClientIP(request); // lấy IP

        // Redirect về trang đăng nhập với lỗi
        if (loginAttemptService.isBlocked(email)) {
            // Tài khoản bị khóa tạm thời
            setDefaultFailureUrl("/login?locked=true");
            logger.info("User '{}' from IP '{}' was blocked at {}", email, ipAddress, LocalDateTime.now());

        } else {
            // Sai tên đăng nhập hoặc mật khẩu
            setDefaultFailureUrl("/login?error=true");
            logger.info("User '{}' from IP '{}' failed to login at {}", email, ipAddress, LocalDateTime.now());
        }
        super.onAuthenticationFailure(request, response, exception);
    }

    // Hàm hỗ trợ lấy địa chỉ IP thật sự (có xét reverse proxy nếu có)
    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0]; // lấy IP đầu tiên trong chuỗi nếu qua proxy
    }
}
