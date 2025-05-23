package hcmute.com.ShoeShop.controller.manager;


import hcmute.com.ShoeShop.dto.OrderDetailDto;
import hcmute.com.ShoeShop.dto.OrderPaymentDto;
import hcmute.com.ShoeShop.dto.OrderStaticDto;
import hcmute.com.ShoeShop.dto.ShipperDto;
import hcmute.com.ShoeShop.entity.Order;
import hcmute.com.ShoeShop.entity.Shipment;
import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.services.imp.OrderDetailServiceImpl;
import hcmute.com.ShoeShop.services.imp.OrderServiceImpl;
import hcmute.com.ShoeShop.services.imp.ShipmentService;
import hcmute.com.ShoeShop.services.imp.UserService;
import hcmute.com.ShoeShop.utlis.ShipmentStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Controller
@RequestMapping("/manager/order")
public class OrderManageController {
        @Autowired
        OrderServiceImpl orderService;
        @Autowired
        OrderDetailServiceImpl orderDetailService;
        @Autowired
        UserService userService;
        @Autowired
        ShipmentService shipmentService;
        @GetMapping
        public String getIn(){
                return "manager/order/order-detail";
        }


        @GetMapping("/list")
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
                return "manager/order/orders-list";
        }

        @GetMapping("/detail/{id}")
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

                return "manager/order/order-detail";
        }

        @GetMapping("/shipping")
        public String addShipping(@RequestParam("orderid") int orderid,
                                  @RequestParam("userid") int userid){
                shipmentService.insertShipment(orderid, userid);
                return "redirect:/manager/order/detail/" + orderid;
        }
}
