package hcmute.com.ShoeShop.controller.admin;

import hcmute.com.ShoeShop.entity.ShippingCompany;
import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.services.imp.ShippingCompanyService;
import hcmute.com.ShoeShop.utlis.Constant;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/admin/shipping_company")
public class AdminShippingCompanyController {

    @Autowired
    private ShippingCompanyService shippingCompanyService;

    @GetMapping("/list")
    public String adminShippingCompany(Model model, HttpSession session) {
        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        if(u==null)
            return "redirect:/login";
        List<ShippingCompany> list = shippingCompanyService.findAll();
        model.addAttribute("shippingCompanies", list);
        return "admin/shippingCompany/shippingCompany_list";
    }

    @GetMapping("/add")
    public String showAddForm(Model model, HttpSession session) {
        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        if(u==null)
            return "redirect:/login";
        return "admin/shippingCompany/sC_add"; // Form for adding a new shipping company
    }

    @PostMapping("/addNew")
    public String addNewShippingCompany(@RequestParam("name") String name,
                                        @RequestParam("fee") int fee,
                                        @RequestParam("status") boolean status, HttpSession session) {
        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        if(u==null)
            return "redirect:/login";
        ShippingCompany shippingCompany = new ShippingCompany();
        shippingCompany.setName(name);
        shippingCompany.setShippingFee(fee);
        shippingCompany.setActive(status);
        shippingCompanyService.saveSC(shippingCompany);
        return "redirect:/admin/shipping_company/list";
    }

    @GetMapping("/delete/{id}")
    public String deleteShippingCompany(@PathVariable int id, HttpSession session) {
        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        if(u==null)
            return "redirect:/login";
        shippingCompanyService.changStatus(shippingCompanyService.findShippingCompanyById(id));
        return "redirect:/admin/shipping_company/list";
    }

    @GetMapping("/edit/{id}")
    public String editShippingCompany(@PathVariable int id, Model model, HttpSession session) {
        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        if(u==null)
            return "redirect:/login";
        model.addAttribute("shippingCompany", shippingCompanyService.findShippingCompanyById(id));
        return "admin/shippingCompany/sC_edit";
    }

    @PostMapping("/edit")
    public String editSC(@RequestParam("name") String name,
                                        @RequestParam("fee") int fee,
                                        @RequestParam("status") boolean status,
                         @RequestParam("id") int id,
                         HttpSession session) {
        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        if(u==null)
            return "redirect:/login";
        ShippingCompany shippingCompany = new ShippingCompany();
        shippingCompany.setId(id);
        shippingCompany.setName(name);
        shippingCompany.setShippingFee(fee);
        shippingCompany.setActive(status);
        shippingCompanyService.saveSC(shippingCompany);
        return "redirect:/admin/shipping_company/list";
    }
}
