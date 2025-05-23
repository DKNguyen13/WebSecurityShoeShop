package hcmute.com.ShoeShop.controller;

import hcmute.com.ShoeShop.entity.Users;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ErrorController {
    @GetMapping("/access-denied")
    public String accessDenied() {
        return "access-denied"; // Tên của file HTML
    }

    @GetMapping("/denied/wating")
    public String denied(HttpSession session) {
        Users user = (Users) session.getAttribute("user");

        if (user == null) {
            return "redirect:/login";
        }
        else{
            if (user.getRole().getRoleName().equals("admin"))
                return "redirect:/admin";
            else if (user.getRole().getRoleName().equals("user"))
                return "redirect:/";
            else if (user.getRole().getRoleName().equals("manager"))
                return "redirect:/manager";
            else
                return "redirect:/shipper/profile";
        }
    }

}
