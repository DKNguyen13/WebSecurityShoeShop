package hcmute.com.ShoeShop.controller.web;

import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.services.imp.EmailService;
import hcmute.com.ShoeShop.services.imp.UserService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttribute;

@Controller
public class ForgotPasswordController {

    @Autowired
    UserService userService;

    @Autowired
    private EmailService emailService;

    String ema;

    @GetMapping("/reset_password")
    public String resetPassword(Model model) {
        model.addAttribute("isEmailSent", false);
        model.addAttribute("isEmailSent1", false);
        model.addAttribute("isCodeVerified", false);
        return "web/reset_password";
    }

    @PostMapping("/sendcode")
    public String sendVerificationCode(@RequestParam String email, HttpSession session, Model model) {
        ema = email;
        Users u = userService.findUserByEmail(ema);
        if(u==null) {
            model.addAttribute("isEmailSent", false);
            model.addAttribute("isEmailSent1", false);
            model.addAttribute("isCodeVerified", false);
        }
        else {
            String verificationCode = String.format("%06d", (int) (Math.random() * 1000000));
            session.setAttribute("verificationCode", verificationCode);

            emailService.sendVerificationCode(email, verificationCode);
            model.addAttribute("message", "Verification code sent to your email!");
            model.addAttribute("isEmailSent", true);
            model.addAttribute("isEmailSent1", true);
            model.addAttribute("isCodeVerified", false);
        }
        return "web/reset_password";
    }

    @PostMapping("/verifycode")
    public String verifyCode(@RequestParam String enteredCode, @SessionAttribute("verificationCode") String verificationCode, Model model) {
        if (enteredCode.equals(verificationCode)) {
            model.addAttribute("isEmailSent", true);
            model.addAttribute("isEmailSent1", false);
            model.addAttribute("isCodeVerified", true);
        } else {
            model.addAttribute("message", "Invalid verification code. Please try again.");
            model.addAttribute("isEmailSent", true);
            model.addAttribute("isEmailSent1", true);
            model.addAttribute("isCodeVerified", false);
        }
        return "web/reset_password";
    }

    @PostMapping("/resetPassword")
    public String resetPassword(@RequestParam("newPassword") String newPassword,
                                @RequestParam("confirmPassword") String confirmPassword, Model model) {
        if (newPassword.equals(confirmPassword)) {
            Users u = userService.findUserByEmail(ema);
            userService.saveUser(u);
            return "redirect:/login";
        } else {
            model.addAttribute("errorMessage", "Passwords do not match!");
            model.addAttribute("isEmailSent", true);
            model.addAttribute("isEmailSent1", false);
            model.addAttribute("isCodeVerified", true);
            return "web/reset_password";
        }
    }
}
