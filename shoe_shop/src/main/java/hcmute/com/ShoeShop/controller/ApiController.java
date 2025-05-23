package hcmute.com.ShoeShop.controller;

import hcmute.com.ShoeShop.dto.OrderReportDto;
import hcmute.com.ShoeShop.dto.ShipperDto;
import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.services.imp.OrderServiceImpl;
import hcmute.com.ShoeShop.services.imp.ShipmentService;
import hcmute.com.ShoeShop.services.imp.UserService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.*;

import java.security.PublicKey;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
public class ApiController {
        @Autowired
        UserService userService;
        @Autowired
        OrderServiceImpl orderService;
        @Autowired
        ShipmentService shipmentService;

        @GetMapping("/shipper/search")
        public List<ShipperDto> searchUser(@RequestParam(value = "name") String name){
                List<Users> listUser = userService.findByFullnameAndRole(name, 4);

                return listUser.stream()
                        .map((user) -> new ShipperDto(user.getId(), user.getFullname()))
                        .collect(Collectors.toList());
        }


        @PostMapping("/order/cancel")
        public void cancelOrder(@RequestParam("orderId") int orderId){
                orderService.cancelOrder(orderId);
        }


        @PostMapping("/shipper/note")
        public void addNote(@RequestParam("note") String note,
                            @RequestParam("shipmentId") int shipmentId){
                shipmentService.updateNote(shipmentId, note);
        }

        @PostMapping("/user/update")
        public void updateUser(@RequestParam("fullname") String fullname,
                               @RequestParam("address") String address,
                               @RequestParam("phone") String phone,
                               HttpSession session){
                Users user = (Users) session.getAttribute("user");
                userService.updateUser(user, fullname, address, phone);
        }

        @GetMapping("/order/report")
        public OrderReportDto orderReport(@RequestParam("startDate") @DateTimeFormat(pattern = "yyyy-MM-dd") Date startDate,
                                          @RequestParam("endDate") @DateTimeFormat(pattern = "yyyy-MM-dd") Date endDate){
                if (startDate.after(endDate)) {
                        throw new IllegalArgumentException("Start date cannot be after end date.");
                }

                return OrderReportDto.builder()
                        .totalOrder(orderService.orderCountByDate(startDate, endDate))
                        .totalPrice(orderService.totalPriceByDate(startDate, endDate))
                        .build();
        }
}
