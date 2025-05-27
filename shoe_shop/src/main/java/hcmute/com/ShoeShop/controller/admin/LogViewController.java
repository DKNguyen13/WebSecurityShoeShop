package hcmute.com.ShoeShop.controller.admin;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@Controller
@RequestMapping("/admin/logs")
@PreAuthorize("hasRole('admin')")
public class LogViewController {

    @GetMapping
    public String viewLogs(Model model) throws IOException {
        String logs = Files.readString(Path.of("logs/app.log"));
        model.addAttribute("logs", logs);
        return "admin/logs"; // trang Thymeleaf hiển thị logs
    }
}
