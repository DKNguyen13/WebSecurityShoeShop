package hcmute.com.ShoeShop.controller;

import hcmute.com.ShoeShop.entity.Users;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

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

    @RequestMapping("/access_error")
    public String handleError(HttpServletRequest request, Model model) {
        // Lấy mã lỗi HTTP
        Object status = request.getAttribute("javax.servlet.error.status_code");

        if (status != null) {
            int statusCode = Integer.parseInt(status.toString());

            // Thêm mã lỗi vào model
            model.addAttribute("status", statusCode);

            // Thêm thông báo lỗi tùy chỉnh dựa trên mã lỗi
            if(statusCode == HttpStatus.NOT_FOUND.value()) {
                model.addAttribute("message", "Trang không tồn tại");
            }
            else if(statusCode == HttpStatus.FORBIDDEN.value()) {
                model.addAttribute("message", "Bạn không có quyền truy cập trang này");
                return "access-denied";
            }
            else if(statusCode == HttpStatus.INTERNAL_SERVER_ERROR.value()) {
                model.addAttribute("message", "Lỗi máy chủ nội bộ");
            }
            else {
                model.addAttribute("message", "Đã xảy ra lỗi không xác định");
            }
        }

        return "error";
    }
}
