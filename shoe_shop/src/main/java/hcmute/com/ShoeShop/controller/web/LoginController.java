package hcmute.com.ShoeShop.controller.web;

import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.services.imp.UserService;
import hcmute.com.ShoeShop.utlis.Constant;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {
    @Autowired
    private UserService userService;
    @Autowired
    PasswordEncoder passwordEncoder;

    @GetMapping("/login")
    public String login(HttpServletRequest req, Model model) {
        Cookie[] cookies = req.getCookies();
        String username = null;
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(Constant.COOKIE_REMEMBER)) {
                    username = cookie.getValue();
                    break;
                }
            }
        }
        if (username != null) {
            model.addAttribute("username", username);
        }
        return "/web/login";
    }

    @PostMapping("/login-process")
    public String loginPost(Model model) {
        model.addAttribute("mess", "Incorrect password or email");
        return "/web/login";
    }

    private void saveRemeberMe(HttpServletResponse resp, String username) {
        Cookie cookie = new Cookie(Constant.COOKIE_REMEMBER, username);
        cookie.setMaxAge(60*60);
        cookie.setHttpOnly(true);  // Set cookie as HttpOnly for security
        cookie.setSecure(true);  // Set cookie to secure (use only over HTTPS)
        resp.addCookie(cookie);
    }
}
