package hcmute.com.ShoeShop.component;

import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.repository.UserRepository;
import hcmute.com.ShoeShop.utlis.Constant;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Autowired
    UserRepository userRepository;

    @Autowired
    LoginAttemptService loginAttemptService;

    private static final Logger logger = LoggerFactory.getLogger("userLogger");

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String email = authentication.getPrincipal().toString();
        HttpSession session = request.getSession();

        // Reset số lần đăng nhập sai
        loginAttemptService.loginSucceeded(email);

        Users userS = userRepository.findByEmail(email);

        // ghi lại log
        logger.info("User '{}' logged in successfully at {}", email, LocalDateTime.now());

        userS.setPass(null); // xoa thong tin nhay cam truoc khi luu vao session
        //luu session
        session.setAttribute(Constant.SESSION_USER, userS);
        //chuyen huong dang nhap
        response.sendRedirect("/waiting");
    }

}
