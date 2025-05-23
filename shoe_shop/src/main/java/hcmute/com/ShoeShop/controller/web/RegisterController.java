package hcmute.com.ShoeShop.controller.web;

import hcmute.com.ShoeShop.entity.Address;
import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.services.imp.AddressService;
import hcmute.com.ShoeShop.services.imp.EmailService;
import hcmute.com.ShoeShop.services.imp.RoleService;
import hcmute.com.ShoeShop.services.imp.UserService;
import org.springframework.beans.factory.annotation.Autowired;
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
                                  @RequestParam("phone") String phone ,
                                  Model model) {
        try{
            Users user = new Users();
            Address adr = new Address();
            if(userService.findUserByEmail(email) == null ) {
                if(verificationCode.equals(verity) && tmp_mail.equals(email)) {
                    //Add user
                    user.setEmail(email);
                    user.setFullname(fullname);
                    user.setAddress(address);
                    user.setPass(password);
                    user.setPhone(phone);
                    user.setRole(roleService.findRoleById(3));
                    userService.saveUser(user);

                    //Add address
                    adr.setUser(user);
                    adr.setAddress(address);
                    adr.setIsDefault(true);
                    addressService.save(adr);

                    return "redirect:/login";
                }
                else {
                    model.addAttribute("mess", "Verity code or email not match");
                    verificationCode = null;
                    return "web/register";
                }
            }
            else {
                model.addAttribute("mess", "Email already in use");
                verificationCode = null;
                return "web/register";
            }
        }
        catch(Exception e){
            e.printStackTrace();
            verificationCode = null;
            model.addAttribute("mess", "Error");
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
            return "error";
        }
    }


    private String generateRandomCode() {
        Random random = new Random();
        int code = random.nextInt(900000) + 100000; // bắt đầu từ 100000 tới 999999
        return String.valueOf(code);
    }
}
