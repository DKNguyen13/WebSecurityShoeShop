package hcmute.com.ShoeShop.controller.admin;

import hcmute.com.ShoeShop.dto.ProductDto;
import hcmute.com.ShoeShop.entity.*;
import hcmute.com.ShoeShop.services.imp.*;
import hcmute.com.ShoeShop.utlis.Constant;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/admin/product")
public class AdminProductController {

    @Autowired
    private ProductService productService;

    @Autowired
    private ProductDetailService productDetailService;

    @Autowired
    private CategoryService categoryService;

    @Autowired
    private WishlistService wishListService;
    @Autowired
    private RatingService ratingService;

    @GetMapping("/insertProductPage")
    public String insertProductPage(Model model) {
        model.addAttribute("categories", categoryService.findAll());
        model.addAttribute("product", new ProductDto());
        return "/admin/products/product-add";
    }

    @PostMapping("/save")
    public String save(@ModelAttribute(name = "product") ProductDto productDto,
                       @RequestParam(name = "image", required = false) MultipartFile image,
                       @RequestParam Map<String, String> productDetails) {
        productService.saveProduct(productDto, image, productDetails);
        return "redirect:/admin/product";
    }

    @GetMapping("/updateProduct/{id}")
    public String getFormUpdateProduct(@PathVariable("id") Long id, Model model) {
        ProductDto productDto = productService.getProductDtoById(id);
        model.addAttribute("product", productDto);
        model.addAttribute("categories", categoryService.findAll());

        Map<Integer, Double> sizePriceMap = productService.getSizePriceMap(id);
        if (sizePriceMap != null) {
            System.out.println("Size Price Map: " + sizePriceMap);
        } else {
            System.out.println("Size Price Map is null!");
        }
        model.addAttribute("sizePriceMap", sizePriceMap);


        return "/admin/products/product-edit";
    }



    @PostMapping("/update")
    public String update(@ModelAttribute(name = "product") ProductDto productDto,
                         @RequestParam(name = "image", required = false) MultipartFile image,
                         @RequestParam Map<String, String> productDetails) {
        productService.updateProduct(productDto, image, productDetails);
        return "redirect:/admin/product";
    }


    @GetMapping("/deleteProduct/{id}")
    public String delete(@PathVariable("id") Long id) {
        productService.deleteProduct(id);
        return "redirect:/admin/product";
    }

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
    public String getProductDetails(@PathVariable long id, ModelMap model, HttpSession session) {
        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        if(u==null)
            return "redirect:/login";
        model.addAttribute("user", u);
        List<Product> wishlist = wishListService.getWishlist(u.getId());
        model.addAttribute("wishlist", wishlist);
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
        return "/user/single-product";
    }

    @GetMapping("")
    public String getAllProduct(@RequestParam(defaultValue = "0") int page,
                                @RequestParam(defaultValue = "3") int size,
                                Model model) {
        Page<Product> productPage = productService.getPaginatedProducts(PageRequest.of(page, size));
        model.addAttribute("products", productPage.getContent());
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", productPage.getTotalPages());
        return "/admin/products/product-list";
    }
}
