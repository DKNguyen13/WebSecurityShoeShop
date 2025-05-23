package hcmute.com.ShoeShop.controller.admin;

import hcmute.com.ShoeShop.entity.Category;
import hcmute.com.ShoeShop.repository.CategoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/admin/category")
public class AdminCategoryController {

    @Autowired
    private CategoryRepository categoryRepository;

    @GetMapping("")
    public String category(Model model) {
        model.addAttribute("categories", categoryRepository.findAll());
        return "admin/categories/category-list";
    }
    @GetMapping("/insertCategoryPage")
    public String insertProductPage(Model model) {
        Category category = new Category();
        model.addAttribute("category", category);
        return "admin/categories/category-add";
    }

    @PostMapping("/save")
    public String save(@ModelAttribute(name = "category") Category category) {
        categoryRepository.save(category);

        return "redirect:/admin/category";
    }

    @GetMapping("/updateCategory/{id}")
    public String getFormUpdateCategory(@PathVariable("id") Long id, Model model){
        Category category = categoryRepository.findById(id).get();
        model.addAttribute("category", category);
        model.addAttribute("id", category.getId());
        return "admin/categories/category-edit";
    }

    @PostMapping("/update")
    public String update(@ModelAttribute(name = "category") Category category) {
        categoryRepository.save(category);
        return "redirect:/admin/category";
    }
    @GetMapping("/deleteCategory/{id}")
    public String delete(@PathVariable("id") Long id){
        categoryRepository.deleteById(id);
        return "redirect:/admin/category";
    }

}