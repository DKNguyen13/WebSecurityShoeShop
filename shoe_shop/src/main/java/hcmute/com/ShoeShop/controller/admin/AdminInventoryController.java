package hcmute.com.ShoeShop.controller.admin;

import hcmute.com.ShoeShop.dto.InventoryDto;
import hcmute.com.ShoeShop.entity.Inventory;
import hcmute.com.ShoeShop.entity.Product;
import hcmute.com.ShoeShop.entity.ProductDetail;
import hcmute.com.ShoeShop.repository.InventoryRepository;
import hcmute.com.ShoeShop.repository.ProductDetailRepository;
import hcmute.com.ShoeShop.repository.ProductRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@Controller
@RequestMapping("/admin/inventory")
public class AdminInventoryController {

    @Autowired
    private InventoryRepository inventoryRepository;
    @Autowired
    private ProductDetailRepository productDetailRepository;

    @GetMapping("")
    public String showInventory(Model model, Pageable pageable) {
        Pageable pageRequest = PageRequest.of(pageable.getPageNumber(), 3);
        Page<Inventory> inventoryPage = inventoryRepository.findAll(pageRequest);

        model.addAttribute("inventories", inventoryPage);
        model.addAttribute("currentPage", pageable.getPageNumber());
        model.addAttribute("totalPages", inventoryPage.getTotalPages());
        model.addAttribute("totalItems", inventoryPage.getTotalElements());

        return "/admin/inventory/inventory-warehouse";
    }
    @GetMapping("/insertPage")
    public String insertProductPage(Model model) {
        InventoryDto inventory = new InventoryDto();
        model.addAttribute("inventory", inventory);
        model.addAttribute("details", productDetailRepository.findAll());
        return "/admin/inventory/inventory-add";
    }

    @PostMapping("/save")
    public String save(@ModelAttribute(name = "inventory") InventoryDto inventoryDto) {
        Inventory inventory = new Inventory();
        ProductDetail detail = productDetailRepository.findById(inventoryDto.getProductDetailId()).get();
        inventory.setQuantity(inventoryDto.getQuantity());
        inventory.setProductDetail(detail);
        inventory.setCreatedAt(LocalDateTime.now());
        inventoryRepository.save(inventory);

        return "redirect:/admin/inventory";
    }

    @GetMapping("/update/{id}")
    public String getFormUpdateCategory(@PathVariable("id") Long id, Model model){
        Inventory inventory = inventoryRepository.findById(id).get();
        InventoryDto inventoryDto = new InventoryDto();
        inventoryDto.setId(inventory.getId());
        inventoryDto.setTitle(inventory.getProductDetail().getProduct().getTitle());
        inventoryDto.setQuantity(inventory.getQuantity());
        inventoryDto.setCreatedAt(inventory.getCreatedAt());
        inventoryDto.setProductDetailId(inventory.getProductDetail().getId());
        System.out.println(inventoryDto);
        model.addAttribute("inventory", inventoryDto);
        model.addAttribute("id", inventory.getId());
        model.addAttribute("details", productDetailRepository.findAll());
        return "/admin/inventory/inventory-edit";
    }

    @PostMapping("/update")
    public String update(@ModelAttribute(name = "inventory") InventoryDto inventoryDto) {
        Inventory inventory = inventoryRepository.findById(inventoryDto.getId()).get();
        ProductDetail product = productDetailRepository.findById(inventoryDto.getProductDetailId()).get();
        inventory.setQuantity(inventoryDto.getQuantity());
        inventory.setProductDetail(product);
        inventory.setCreatedAt(LocalDateTime.now());
        inventoryRepository.save(inventory);
        return "redirect:/admin/inventory";
    }
    @GetMapping("/delete/{id}")
    public String delete(@PathVariable("id") Long id){
        inventoryRepository.deleteById(id);
        return "redirect:/admin/inventory";
    }

}