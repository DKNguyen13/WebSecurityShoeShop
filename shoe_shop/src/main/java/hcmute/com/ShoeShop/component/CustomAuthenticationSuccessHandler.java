package hcmute.com.ShoeShop.component;

import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.repository.UserRepository;
import hcmute.com.ShoeShop.utlis.Constant;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Autowired
    UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String email = authentication.getPrincipal().toString();
        HttpSession session = request.getSession();

        Users userS = userRepository.findByEmail(email);

        System.out.println(userS);
        //luu session
        session.setAttribute(Constant.SESSION_USER, userS);
        //chuyen huong dang nhap
        response.sendRedirect("/waiting");
    }

}
