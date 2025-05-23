package hcmute.com.ShoeShop.controller.user;

import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.utlis.Constant;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import hcmute.com.ShoeShop.services.imp.WishlistService;

import java.util.Map;

@Controller
@RequestMapping("/wishlist")
public class WishListController {
    @Autowired
    private WishlistService wishListService;

    @PostMapping("/toggle")
    @ResponseBody
    public String toggleWishlist(@RequestBody Map<String, Object> requestData, HttpSession session) {
        Long productId = Long.valueOf(requestData.get("productId").toString());

        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        if (u == null) {
            return "LOGIN_REQUIRED";
        }

        boolean isAdded = wishListService.toggleWishlist(u.getId(), productId);
        if (isAdded) {
            return "ADDED"; // Sản phẩm đã được thêm vào wishlist
        } else {
            return "REMOVED"; // Sản phẩm đã bị xóa khỏi wishlist
        }
    }

    @PostMapping("/delete")
    @ResponseBody
    public String deleteProduct(@RequestBody Map<String, Object> requestData, HttpSession session) {
        Long productId = Long.valueOf(requestData.get("productId").toString());
        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        System.out.println(productId+ "user" + u.getId());
        if (u == null) {
            return "LOGIN_REQUIRED"; // Nếu người dùng chưa đăng nhập
        }

        // Tìm và xóa sản phẩm khỏi Wishlist
        boolean success = wishListService.deleteProductFromWishlist(u.getId(), productId);
        if (success) {
            return "SUCCESS"; // Xóa thành công
        } else {
            return "ERROR"; // Lỗi khi xóa sản phẩm
        }
    }
}
