package hcmute.com.ShoeShop.controller;

import hcmute.com.ShoeShop.entity.Category;
import hcmute.com.ShoeShop.entity.Product;
import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.repository.CategoryRepository;
import hcmute.com.ShoeShop.services.imp.ProductService;
import hcmute.com.ShoeShop.services.imp.WishlistService;
import hcmute.com.ShoeShop.utlis.Constant;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/category")
public class CategoryController {

    @Autowired
    private CategoryRepository categoryRepository;

    @Autowired
    private ProductService productService;

    @GetMapping("/{id}")
    public String getCategoryContent(@PathVariable("id") Long id, ModelMap model,
                                     @RequestParam(defaultValue = "0") int page,
                                     @RequestParam(defaultValue = "6") int size){
        Category cate = categoryRepository.findById(id).get();
        if(cate == null){

            return "Can not find by category ID: " + id;
        }

        Page<Product> productsPage = productService.getPaginatedProductsByCategory(id, PageRequest.of(page, size));
        if (productsPage.isEmpty()) {

            return "No products found for this category.";
        }

        model.addAttribute("products", productsPage);
        model.addAttribute("currentPage", productsPage.getNumber());
        model.addAttribute("totalPages", productsPage.getTotalPages());
        return "user/product-list";
    }

}