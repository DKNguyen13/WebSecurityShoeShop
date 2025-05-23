package hcmute.com.ShoeShop.controller;

import hcmute.com.ShoeShop.dto.ProductDto;
import hcmute.com.ShoeShop.entity.*;
import hcmute.com.ShoeShop.services.imp.*;
import hcmute.com.ShoeShop.utlis.Constant;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.Banner;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/product")
public class ProductController {

    @Autowired
    private ProductService productService;

    @Autowired
    private ProductDetailService productDetailService;

    @Autowired
    private WishlistService wishListService;
    @Autowired
    private RatingService ratingService;

    @Autowired
    private CategoryService categoryService;


    @GetMapping("/web")
    public String getAllProducts(@RequestParam(defaultValue = "0") int page,
                                 @RequestParam(defaultValue = "6") int size,
                                 Model model) {
        Page<Product> productPage = productService.getPaginatedProducts(PageRequest.of(page, size));
        model.addAttribute("products", productPage.getContent());
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", productPage.getTotalPages());
        return "redirect:/";
    }

    @GetMapping("/details/{id}")
    public String getProductDetails(@PathVariable long id, Model model, HttpSession session) {
        Users u = (Users) session.getAttribute(Constant.SESSION_USER);


        List<Long> viewedProductIds = (List<Long>) session.getAttribute(Constant.VIEW_PRODUCT);

        if (viewedProductIds == null) {
            viewedProductIds = new ArrayList<>();
        }
        // Thêm sản phẩm vào danh sách nếu chưa có
        if (!viewedProductIds.contains(id)) {
            viewedProductIds.add(id);
        }

        if(u != null) {

            // Lưu lại vào session
            session.setAttribute(Constant.VIEW_PRODUCT, viewedProductIds);
            model.addAttribute("user", u);
            List<Product> wishlist = wishListService.getWishlist(u.getId());
            model.addAttribute("wishlist", wishlist);
        }

        // Truyền thông báo nếu có
        String alert = (String) model.asMap().get("alert");

        System.out.println(alert);
        model.addAttribute("alert", alert);


        Product product = productService.getProductById(id);
        List<ProductDetail> productDetails = productDetailService.findProductByProductId(id);
        model.addAttribute("productDetails", productDetails);
        model.addAttribute("product", product);

        int totalRating = ratingService.countRatingsByProductId(id);
        model.addAttribute("totalRating", totalRating);

        List<Rating> ratings = ratingService.getAllRatingsByProductId(id);

        // Tính trung bình số sao
        double averageStar = ratings.stream().mapToInt(Rating::getStar).average().orElse(0.0);
        averageStar = Math.round(averageStar * 10) / 10.0;
        model.addAttribute("avgrating", averageStar);
        return "user/single-product";
    }

    @GetMapping("/search/all")
    public String getAllProductsByKeyForShop(@RequestParam(value = "key", required = false, defaultValue = "") String key,
                                      Model model,
                                      @RequestParam(value = "category", required = false) Long categoryId,
                                      @RequestParam(defaultValue = "0") int page,
                                      @RequestParam(defaultValue = "6") int size) {

        List<Category> categories = categoryService.findAll();
        model.addAttribute("cate", categories);

        Page<Product> products;
        if (categoryId != null) {
            // Tìm kiếm theo category và keyword
            products = productService.searchProductsByCategoryAndTitle(categoryId, key, PageRequest.of(page, size));
        }
        else {
            products = productService.searchProductsByTitle(key, PageRequest.of(page, size));
        }
        if(products.isEmpty()){
            model.addAttribute("alert", "Không tồn tại sản phẩm bạn muốn tìm!");
        }

        model.addAttribute("products", products.getContent());
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", products.getTotalPages());
        return "user/shop";
    }

    @GetMapping("/search/all/index")
    public String getAllProductsByKeyForIndex(@RequestParam(value = "key", required = false, defaultValue = "") String key,
                                             Model model,
                                             @RequestParam(value = "category", required = false) Long categoryId,
                                             @RequestParam(defaultValue = "0") int page,
                                             @RequestParam(defaultValue = "6") int size) {

        List<Category> categories = categoryService.findAll();
        model.addAttribute("categories", categories);

        Page<Product> products;
        if (categoryId != null) {
            // Tìm kiếm theo category và keyword
            products = productService.searchProductsByCategoryAndTitle(categoryId, key, PageRequest.of(page, size));
        }
        else {
            products = productService.searchProductsByTitle(key, PageRequest.of(page, size));
        }
        if(products.isEmpty()){
            model.addAttribute("alert", "Không tồn tại sản phẩm bạn muốn tìm!");
        }

        model.addAttribute("products", products.getContent());
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", products.getTotalPages());
        // lay ra list 20 san pham co rating cao nhat
        List<Product> ratedProducts = productService.getTopRatedProducts();
        model.addAttribute("ratedProducts", ratedProducts);
        return "web/index";
    }
}