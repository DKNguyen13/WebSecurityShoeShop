package hcmute.com.ShoeShop.controller.user;

import hcmute.com.ShoeShop.entity.*;
import hcmute.com.ShoeShop.services.imp.*;
import hcmute.com.ShoeShop.utlis.Constant;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.stream.Collectors;

import hcmute.com.ShoeShop.entity.Product;
import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.services.imp.ProductService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;


@Controller
@RequestMapping("/user")
public class UserHomeController {

    @Autowired
    private UserService userService;

    @Autowired
    private CategoryService categoryService;

    @Autowired
    private ProductService productService;

    @Autowired
    private AddressService addressService;

    @Autowired
    private WishlistService wishListService;

    @GetMapping("/shop")
    public String userHome(HttpSession session, Model model,
                           @RequestParam(defaultValue = "0") int page,
                           @RequestParam(defaultValue = "6") int size) {
        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        if (u != null) {
            List<Category> categories = categoryService.findAll();
            List<Product> wishlist = wishListService.getWishlist(u.getId());
            int cateCount = categoryService.count();
            if (categories != null && cateCount > 0) {
                Pageable pageable = PageRequest.of(page, size);
                Page<Product> productsPage = productService.findAllPage(pageable);

                model.addAttribute("cate", categories);
            } else {
                model.addAttribute("cate", null);
            }
            model.addAttribute("wishlist", wishlist);
            model.addAttribute("user", u);
            Page<Product> productPage = productService.getPaginatedProducts(PageRequest.of(page, size));

            model.addAttribute("products", productPage.getContent());
            model.addAttribute("currentPage", page);
            model.addAttribute("totalPages", productPage.getTotalPages());
            return "user/shop";
        } else {
            return "redirect:/login";
        }
    }

    @GetMapping("/my_account")
    public String myAccount(HttpSession session, Model model, RedirectAttributes redirectAttributes) {
        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        if (u != null) {
            List<Long> viewedProductIds = (List<Long>) session.getAttribute(Constant.VIEW_PRODUCT);
            if (viewedProductIds == null || viewedProductIds.isEmpty()) {
                redirectAttributes.addFlashAttribute("message", "No products viewed yet.");
            }else {
                // Lọc ra các sản phẩm hợp lệ từ danh sách ID đã xem và loại bỏ sản phẩm đã bị xóa
                List<Product> viewedProducts = productService.getProductsByIds(viewedProductIds);
                // Lọc các sản phẩm đã bị xóa (isDelete == true) và loại bỏ chúng khỏi danh sách
                viewedProducts = viewedProducts.stream()
                        .filter(product -> product != null && !product.isDelete())  // Loại bỏ sản phẩm null và đã xóa
                        .collect(Collectors.toList());

                // Cập nhật lại sản phẩm đã xem trong session
                viewedProductIds = viewedProducts.stream()
                        .map(Product::getId)  // Lấy ID của các sản phẩm còn lại
                        .collect(Collectors.toList());

                // Lưu lại danh sách các sản phẩm hợp lệ vào session
                session.setAttribute(Constant.VIEW_PRODUCT, viewedProductIds);
                model.addAttribute("viewedProducts", viewedProducts);
            }
            // Lấy thông tin sản phẩm từ danh sách ID đã xem
            List<Product> viewedProducts = productService.getProductsByIds(viewedProductIds);
            model.addAttribute("viewedProducts", viewedProducts);
            model.addAttribute("user", u);
            List<Address> adr = addressService.getAddressesByID(u.getId());
            model.addAttribute("adr", adr);
            return "user/my-account";
        } else {
            return "redirect:/login";
        }
    }

    @PostMapping("/resetPassword")
    public String resetPassword(@RequestParam("email") String email,
                                @RequestParam("currentPassword") String currentPassword,
                                @RequestParam("newPassword") String newPassword,
                                @RequestParam("confirmPassword") String confirmPassword,
                                HttpSession session, RedirectAttributes redirectAttributes) {
        try {

            Users u = (Users) session.getAttribute(Constant.SESSION_USER);
            Users us = userService.findUserByEmail(email);
            if (us == null) {
                return "redirect:/login";
            }
            redirectAttributes.addFlashAttribute("user", us);
            if (!newPassword.equals(confirmPassword)) {
                redirectAttributes.addFlashAttribute("error", "New Password and Confirm Password do not match.");
                return "redirect:/user/my_account";
            }
            if (u.getPass().equals(currentPassword)) {
                u.setPass(newPassword);
                userService.saveUser(u);
                redirectAttributes.addFlashAttribute("success", "Password has been reset successfully.");
                return "redirect:/user/my_account";
            } else if (!u.getPass().equals(currentPassword)){
                redirectAttributes.addFlashAttribute("error", "Current password do not match.");
                return "redirect:/user/my_account";
            }
            return "redirect:/user/my_account";
        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/login";
        }
    }

    @PostMapping("/changeInformation")
    public String changMyProfile(@RequestParam("fullname") String fullname,
                                 @RequestParam("phone") String phone,
                                 @RequestParam("address") String adr,
                                 HttpSession session, RedirectAttributes redirectAttributes) {
        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        if (u == null) {
            return "redirect:/login";
        }
        u.setFullname(fullname);
        u.setPhone(phone);
        u.setAddress(adr);
        userService.saveUser(u);
        redirectAttributes.addFlashAttribute("success1", "User has been changed successfully.");
        return "redirect:/user/my_account";  // Sau khi th�nh c�ng, chuy?n t?i trang my-account
    }


    @PostMapping("/addresses")
    public String addresses(@RequestParam("newAddress") String newAddr,
                            HttpSession session, RedirectAttributes redirectAttributes){
        try{
            Users u = (Users) session.getAttribute(Constant.SESSION_USER);
            if(u == null){
                return "redirect:/login";
            }
            redirectAttributes.addFlashAttribute("user", u);
            Address adr = new Address();
            adr.setAddress(newAddr);
            adr.setUser(u);
            adr.setIsDefault(false);
            addressService.save(adr);
            return "redirect:/user/my_account";

        }
        catch (Exception e){
            e.printStackTrace();
        }
        return "redirect:/login";
    }

    @PostMapping("/submitAddress")
    public String handleAddressAction(@RequestParam("selectedAddressId") Integer addressId,
                                      @RequestParam("action") String action,
                                        HttpSession session,
                                      RedirectAttributes redirectAttributes) {
        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        if(u == null){
            return "redirect:/login";
        }
        Address addr = addressService.findById(addressId);
        redirectAttributes.addFlashAttribute("user", u);
        if ("setDefault".equals(action)) {
            addressService.setDefaultAddress(u.getId(),addressId);
            u.setAddress(addr.getAddress());
        } else if ("delete".equals(action)) {
            if (addr != null && addr.getIsDefault()==false) {
                addressService.delete(addr);
            }
            else{
                redirectAttributes.addFlashAttribute("er", "Address can't be deleted. This is defaults address");
            }
        }
        return "redirect:/user/my_account";
    }

    @GetMapping("/wishlist")
    public String wishlist(HttpSession session, Model model) {
        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        if(u == null){
            return "redirect:/login";
        }
        List<Product> wishlist = wishListService.getWishlist(u.getId());
        model.addAttribute("user",u);
        model.addAttribute("wishlist", wishlist);
        return "user/wishlist";
    }

    @GetMapping("/blog")
    public String userBlog(){
        return "user/blog";
    }
}
