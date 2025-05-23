package hcmute.com.ShoeShop.controller.admin;

import hcmute.com.ShoeShop.dto.DiscountDTO;
import hcmute.com.ShoeShop.dto.OrderDetailDto;
import hcmute.com.ShoeShop.dto.OrderPaymentDto;
import hcmute.com.ShoeShop.dto.OrderStaticDto;
import hcmute.com.ShoeShop.entity.*;
import hcmute.com.ShoeShop.services.imp.DiscountService;
import hcmute.com.ShoeShop.services.imp.OrderDetailServiceImpl;
import hcmute.com.ShoeShop.services.imp.OrderServiceImpl;
import hcmute.com.ShoeShop.services.imp.ShipmentService;
import hcmute.com.ShoeShop.utlis.Constant;
import hcmute.com.ShoeShop.utlis.ShipmentStatus;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Controller
@RequestMapping("/admin")
public class AdminHomeController {
    @Autowired
    DiscountService discountService;

    @Autowired
    OrderServiceImpl orderService;
    @Autowired
    OrderDetailServiceImpl orderDetailService;
    @Autowired
    ShipmentService shipmentService;
    @GetMapping
    public String adminHome(RedirectAttributes redirectAttributes, HttpSession session, Model model) {
        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        if(u == null) {
            return "redirect:/login";
        }
        redirectAttributes.addFlashAttribute("user", u);
        Pageable pageable = PageRequest.of(0, 5, Sort.by("createdDate").descending());
        Page<Order> orderPage = orderService.findAll(pageable);
        model.addAttribute("listOrder", orderPage);

        long totalOrder = orderService.countOrder();
        model.addAttribute("totalOrder", totalOrder);

        double totalPrice = orderService.totalPrice().orElse(0.0);
        model.addAttribute("totalPrice", totalPrice);

        return "admin/index";
    }

    @GetMapping("/discount-list")
    public String discountList(HttpSession session, Model model,
                               @RequestParam(defaultValue = "0") int page,
                               @RequestParam(defaultValue = "4") int size) {
        Users u = (Users) session.getAttribute(Constant.SESSION_USER);

        if(u == null) {
            return "redirect:/login";
        }
        List<Discount> li = discountService.findAllDiscounts();

        Page<Discount> discountPage = discountService.findAllDiscounts(PageRequest.of(page, size));
        model.addAttribute("disco", discountPage.getContent());  // Các bản ghi của trang hiện tại
        model.addAttribute("currentPage", page);  // Trang hiện tại
        model.addAttribute("totalPages", discountPage.getTotalPages());  // Tổng số trang
        model.addAttribute("totalElements", discountPage.getTotalElements());  // Tổng số bản ghi
        model.addAttribute("size", size);  // Kích thước của mỗi trang

        model.addAttribute("user", u);
        return "admin/discount/discount_list";
    }

    @GetMapping("/discount-add")
    public String discountAdd(RedirectAttributes redirectAttributes, HttpSession session) {

        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        if(u == null) {
            return "redirect:/login";
        }
        redirectAttributes.addFlashAttribute("user", u);

        return "admin/discount/discount_add";
    }

    @PostMapping("/discount/add")
    public String addDiscount(@ModelAttribute DiscountDTO discountDTO, HttpSession session) {
        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        if(u == null) {
            return "redirect:/login";
        }
        if(discountDTO.getStatus()==null){
            return "redirect:/discount-list";
        }
        else{
            System.out.println(discountDTO.getStatus());
        }
        // Chuyển đổi ngày tháng từ String thành LocalDate
        LocalDate start = LocalDate.parse(discountDTO.getStartDate());
        LocalDate end = LocalDate.parse(discountDTO.getEndDate());

        Discount discount = new Discount();
        discount.setName(discountDTO.getName());
        discount.setPercent(discountDTO.getPercent()/100.0);
        discount.setMinOrderValue(discountDTO.getMinOrderValue());
        discount.setStatus(discountDTO.getStatus());
        discount.setStartDate(start);
        discount.setEndDate(end);
        discountService.saveDiscount(discount);
        return "redirect:/admin/discount-list";
    }

    @GetMapping("/discount-delete/{id}")
    public String deleteDiscount(@PathVariable("id") int id, HttpSession session) {

        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        if(u == null) {
            return "redirect:/login";
        }

        Discount d = discountService.findDiscountById(id);
        d.setStatus("EXPIRED");
        discountService.saveDiscount(d);
        return "redirect:/admin/discount-list";
    }

    @GetMapping("/discount-edit/{id}")
    public String editDiscount(@PathVariable("id") int id, Model model) {
        Discount d = discountService.findDiscountById(id);
        model.addAttribute("discount", d);
        return "admin/discount/discount_edit";
    }

    @PostMapping("/discount/edit")
    public String editDiscount(@ModelAttribute DiscountDTO discountDTO, HttpSession session, @RequestParam("id") int id) {

        Users u = (Users) session.getAttribute(Constant.SESSION_USER);
        if(u == null) {
            return "redirect:/login";
        }

        // Chuyển đổi ngày tháng từ String thành LocalDate
        LocalDate start = LocalDate.parse(discountDTO.getStartDate());
        LocalDate end = LocalDate.parse(discountDTO.getEndDate());
        LocalDate date = LocalDate.parse(discountDTO.getCreatedDate());

        Discount discount = new Discount();
        discount.setId(id);
        discount.setName(discountDTO.getName());
        discount.setCreatedDate(date);
        discount.setPercent(discountDTO.getPercent()/100.0);
        discount.setMinOrderValue(discountDTO.getMinOrderValue());
        discount.setStatus(discountDTO.getStatus());
        discount.setStartDate(start);
        discount.setEndDate(end);
        discountService.saveDiscount(discount);
        return "redirect:/admin/discount-list";
    }

    @GetMapping("/order/list")
    public String getAllOrders(@RequestParam(value = "page-size", defaultValue = "5")int pagesize,
                               @RequestParam(name = "page-num", defaultValue = "0") int pageNum,
                               @RequestParam(name = "status", defaultValue = "") String status,
                               Model model){
        Pageable pageable = PageRequest.of(pageNum, pagesize);

        model.addAttribute("title", "Order");

        Page<Order> listOder = null;

        if (status.isEmpty()){
            listOder = orderService.findAll(pageable);
        }
        else{
            listOder = orderService.findOrderByStatus(ShipmentStatus.valueOf(status), pageable);
        }

        model.addAttribute("listOrder", listOder);

        int totalPages = listOder.getTotalPages();
        model.addAttribute("totalPages", totalPages);
        if (totalPages > 0){
            List<Integer> pageNumbers = IntStream.rangeClosed(1, totalPages)
                    .boxed()
                    .collect(Collectors.toList());
            model.addAttribute("pageNumbers", pageNumbers);
        }

        OrderStaticDto orderStaticDto = orderService.getStatic();
        model.addAttribute("static", orderStaticDto);


        //add status
        model.addAttribute("stt", status);
        return "admin/order/orders-list";
    }
    @GetMapping("/order/detail/{id}")
    public String getOrderDetail(@PathVariable("id") int orderId,
                                 Model model){
        model.addAttribute("title", "Order detail");

        //add list order detail to view
        List<OrderDetailDto> list = orderDetailService.findAllOrderDetailById(orderId);
        model.addAttribute("list", list);

        //add payment detail to view
        OrderPaymentDto orderPaymentDto = orderDetailService.getOrderPayment(orderId);
        model.addAttribute("payment", orderPaymentDto);

        //add order to view
        Order order = orderService.findById(orderId);
        model.addAttribute("order", order);

        //add user detail to view
        Users user = order.getUser();
        model.addAttribute("user", user);

        //add shipper to view
        Shipment shipment = shipmentService.findShipmentByOrderId(orderId);
        model.addAttribute("shipper", shipment);

        return "admin/order/order-detail";
    }

}
