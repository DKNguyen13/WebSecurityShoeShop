package hcmute.com.ShoeShop.controller.web;

import hcmute.com.ShoeShop.entity.*;
import hcmute.com.ShoeShop.services.imp.*;
import hcmute.com.ShoeShop.utlis.Constant;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Iterator;
import java.util.Set;

import java.util.List;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/cart")
public class CartController {

    @Autowired
    CartService cartService;

    @Autowired
    private AddressService addressService;

    @Autowired
    private DiscountService discountService;

    @Autowired
    private ShippingCompanyService shippingCompanyService;

    @GetMapping("/view")
    public String viewCart(HttpSession session, Model model) {
        // lay thong tin nguoi dung tu session
        Users logginedUser = (Users) session.getAttribute(Constant.SESSION_USER);
        if (logginedUser == null) {
            return "redirect:/login";
        }
        List<Address> adr = addressService.getAddressesByID(logginedUser.getId());
        model.addAttribute("adr", adr);
        String email = logginedUser.getEmail();

        Cart cart = cartService.getCartByUser(email);

        // duyet qua set cartDetail kiem tra product isdelete = true thi xoa khoi cart
        Set<CartDetail> cartDetails = cart.getOrderDetailSet();
        cartService.cleanCart(cartDetails, cart);

        List<Discount> discounts = discountService.findAllDiscountsCondition(cart.getTotalPrice());
        model.addAttribute("discounts", discounts);

        List<ShippingCompany> shippingCompanyList = shippingCompanyService.findShippingCompaniesActive();
        model.addAttribute("shippingCompanies", shippingCompanyList);


        // Truyền thông báo nếu có
        String alert = (String) model.asMap().get("alert");

        System.out.println(alert);
        model.addAttribute("alert", alert);

        model.addAttribute("cart", cart);

        return "/user/cart";
    }

    @PostMapping("/add")
    public String addCart(@RequestParam int productDetailId, @RequestParam int quantity, HttpSession session,
                          RedirectAttributes redirectAttributes) {
        // lay thong tin nguoi dung tu session
        Users logginedUser = (Users) session.getAttribute(Constant.SESSION_USER);
        if (logginedUser == null) {
            return "redirect:/login";
        }

        String email = logginedUser.getEmail();

        // goi ham add to cart
        if(!cartService.addToCart(email, productDetailId, quantity)){
            String alert = "Product is sold out!";
            redirectAttributes.addFlashAttribute("alert", alert);
            return "redirect:/cart/view";
        }
        else {
            String alert = "Add product successful!";
            // Dùng RedirectAttributes để giữ lại dữ liệu sau redirect
            redirectAttributes.addFlashAttribute("alert", alert);

            // return ve trang view gio hang
            return "redirect:/cart/view";
        }

    }

    @GetMapping("/delete/{id}")
    public String deleteCart(@PathVariable("id") long cartDetailId, HttpSession session,
                             RedirectAttributes redirectAttributes) {

        Users logginedUser = (Users) session.getAttribute(Constant.SESSION_USER);
        if (logginedUser == null) {
            return "redirect:/login";
        }
        String email = logginedUser.getEmail();

        // xoa khoi gio hang
        cartService.removeFromCart(email, cartDetailId);

        String alert = "Delete product successful!";
        // Dùng RedirectAttributes để giữ lại dữ liệu sau redirect
        redirectAttributes.addFlashAttribute("alert", alert);

        // tra ve view
        return "redirect:/cart/view";
    }

    @PostMapping("/edit/{id}")
    public String editCart(@PathVariable("id") long cartDetailId, @RequestParam int quantity,
                           HttpSession session, RedirectAttributes redirectAttributes) {

        // lay thong tin khach hang
        Users logginedUser = (Users) session.getAttribute(Constant.SESSION_USER);

        if (logginedUser == null) {

            return "redirect:/login";
        }

        String email = logginedUser.getEmail();

        // update gio hang
        cartService.updateMyCart(email, cartDetailId, quantity);

        String alert = "Update product successful!";
        // Dùng RedirectAttributes để giữ lại dữ liệu sau redirect
        redirectAttributes.addFlashAttribute("alert", alert);

        return "redirect:/cart/view";
    }

}
