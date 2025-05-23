package hcmute.com.ShoeShop.controller.admin;

import hcmute.com.ShoeShop.entity.Role;
import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.repository.*;
import hcmute.com.ShoeShop.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/admin/permission")
public class AdminPermissionController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @GetMapping()
    public String index(Model model) {
        // Fetch all users and roles from the database
        model.addAttribute("users", userRepository.findAll());
        model.addAttribute("roles", roleRepository.findAll());
        model.addAttribute("admin", userRepository.countByRole(roleRepository.findById(1).get()));
        model.addAttribute("manager", userRepository.countByRole(roleRepository.findById(2).get()));
        model.addAttribute("shipper", userRepository.countByRole(roleRepository.findById(4).get()));
        model.addAttribute("user", userRepository.countByRole(roleRepository.findById(3).get()));
        return "admin/permission/pages-permissions";
    }

    @PostMapping("/assignRole")
    @ResponseBody
    public String assignRole(@RequestParam int userId, @RequestParam int roleId) {
        try {
            Users user = userRepository.findById(userId).orElseThrow(() -> new IllegalArgumentException("Invalid user Id"));
            Role role = roleRepository.findById(roleId).orElseThrow(() -> new IllegalArgumentException("Invalid role Id"));
            user.setRole(role);
            userRepository.save(user);
            return "success";
        } catch (Exception e) {
            return "error";
        }
    }

}
