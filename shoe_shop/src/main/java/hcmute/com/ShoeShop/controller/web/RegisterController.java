package hcmute.com.ShoeShop.controller.web;

import hcmute.com.ShoeShop.entity.Address;
import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.services.imp.AddressService;
import hcmute.com.ShoeShop.services.imp.EmailService;
import hcmute.com.ShoeShop.services.imp.RoleService;
import hcmute.com.ShoeShop.services.imp.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Random;

@Controller
public class RegisterController {
    @Autowired
    UserService userService;

    @Autowired
    RoleService roleService;

    @Autowired
    EmailService emailService;

    @Autowired
    AddressService addressService;

    private String verificationCode = null;

    String tmp_mail = "";

    @Autowired
    PasswordEncoder passwordEncoder;

    @GetMapping("/register")
    public String registerUser(){
        return "web/register";
    }

    @PostMapping("/register")
    public String processRegister(@RequestParam("email") String email,
                                  @RequestParam("password") String password,
                                  @RequestParam("fullname") String fullname,
                                  @RequestParam("address") String address,
                                  @RequestParam("verity") String verity,
                                  @RequestParam("phone") String phone,
                                  Model model) {
        try {
            // Kiểm tra định dạng email
            if (!email.matches("^[\\w.-]+@[\\w.-]+\\.\\w{2,}$")) {
                model.addAttribute("mess", "Invalid email format.");
                return "web/register";
            }

            // Kiểm tra họ tên không được để trống
            if (fullname == null || fullname.trim().isEmpty()) {
                model.addAttribute("mess", "Fullname is required.");
                return "web/register";
            }

            // Kiểm tra địa chỉ không được để trống
            if (address == null || address.trim().isEmpty()) {
                model.addAttribute("mess", "Address is required.");
                return "web/register";
            }

            // Kiểm tra số điện thoại hợp lệ (10 chữ số, bắt đầu bằng 0)
            if (!phone.matches("^0\\d{9}$")) {
                model.addAttribute("mess", "Invalid phone number format.");
                return "web/register";
            }

            // Kiểm tra mật khẩu: ít nhất 6 ký tự, 1 ký tự in hoa, 1 ký tự đặc biệt
            if (!password.matches("^(?=.*[A-Z])(?=.*[\\W_]).{6,}$")) {
                model.addAttribute("mess", "Password must be at least 6 characters, contain an uppercase letter and a special character.");
                return "web/register";
            }

            // Kiểm tra mã xác thực: đúng 6 chữ số
            if (!verity.matches("^\\d{6}$")) {
                model.addAttribute("mess", "Verification code must be exactly 6 digits.");
                return "web/register";
            }

            // Kiểm tra email đã tồn tại chưa
            if (userService.findUserByEmail(email) != null) {
                model.addAttribute("mess", "Email already in use.");
                verificationCode = null;
                return "web/register";
            }

            // Kiểm tra mã xác thực và email
            if (!verificationCode.equals(verity) || !tmp_mail.equals(email)) {
                model.addAttribute("mess", "Verification code or email does not match.");
                verificationCode = null;
                return "web/register";
            }

            // Tạo và lưu user
            Users user = new Users();
            user.setEmail(email);
            user.setFullname(fullname);
            user.setAddress(address);
            user.setPass(passwordEncoder.encode(password));
            user.setPhone(phone);
            user.setRole(roleService.findRoleById(3));
            userService.saveUser(user);

            // Tạo và lưu địa chỉ mặc định
            Address adr = new Address();
            adr.setUser(user);
            adr.setAddress(address);
            adr.setIsDefault(true);
            addressService.save(adr);

            return "redirect:/login";

        } catch (Exception e) {
            e.printStackTrace();
            verificationCode = null;
            model.addAttribute("mess", "An unexpected error occurred.");
            return "web/register";
        }
    }

    @PostMapping("/send-code")
    @ResponseBody
    public String sendVerificationCode(@RequestParam("email") String email) {
        try {
            if (userService.findUserByEmail(email) == null) {
                verificationCode = generateRandomCode();
                tmp_mail = email;
                // Gửi email với mã xác minh
                emailService.sendVerificationCode(email, verificationCode);
                return "success";
            } else {
                tmp_mail = "";
                return "email_exists";
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(e.getMessage());
            return "error" + e.getMessage();
        }
    }


    private String generateRandomCode() {
        Random random = new Random();
        int code = random.nextInt(900000) + 100000; // bắt đầu từ 100000 tới 999999
        return String.valueOf(code);
    }
}
