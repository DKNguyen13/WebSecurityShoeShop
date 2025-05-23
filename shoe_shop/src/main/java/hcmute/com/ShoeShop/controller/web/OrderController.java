package hcmute.com.ShoeShop.controller.web;

import hcmute.com.ShoeShop.dto.OrderDetailDto;
import hcmute.com.ShoeShop.dto.OrderPaymentDto;
import hcmute.com.ShoeShop.entity.*;
import hcmute.com.ShoeShop.repository.CartRepository;
import hcmute.com.ShoeShop.repository.OrderDetailRepository;
import hcmute.com.ShoeShop.repository.OrderRepository;
import hcmute.com.ShoeShop.services.imp.*;
import hcmute.com.ShoeShop.utlis.PayOption;
import hcmute.com.ShoeShop.utlis.ShipmentStatus;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/order")
public class OrderController {
    @Autowired
    OrderServiceImpl orderService;

    @Autowired
    CartService cartService;

    @Autowired
    OrderDetailServiceImpl orderDetailService;

    @Autowired
    ShipmentService shipmentService;

    @Autowired
    DiscountService discountService;

    private Long shippingFee;
    private Long subtotal;
    private Long total;
    private Boolean orderSuccess;
    private String address;

    private String transactionNo;
    private String orderInfo;
    private String transactionStatus;
    private Long cartId;
    @GetMapping()
    public String order(@RequestParam(value = "page-size", defaultValue = "10")int pagesize,
                        @RequestParam(name = "page-num", defaultValue = "0") int pageNum,
                        Model model,
                        HttpSession session) {
        Pageable pageable = PageRequest.of(pageNum, pagesize, Sort.by("status"));
        Users user = (Users) session.getAttribute("user");
        int userId = user.getId();
        Page<Order> orderPage = orderService.findOrderByUserId(userId, pageable);

        model.addAttribute("orderPage", orderPage);
//        orderService.orderCart(2, 150, PayOption.COD);
        return "/user/order";
    }

    @PostMapping("/pay")
    public String handlePayment(@RequestParam("cartId") Long cartId,
                                @RequestParam(value = "finalTotalPrice" , required = false) String finalPrice,
                                @RequestParam(value = "addressId") String address,
                                @RequestParam("payOption") String payOption) throws UnsupportedEncodingException {
        this.address = address;

        // Lấy Cart từ CartId
        Cart cart = cartService.findById(cartId);
        if((finalPrice != null) && (Double.parseDouble(finalPrice) != 0) && (!finalPrice.equals(""))){
            cart.setId(cartId.intValue());
            cart.setTotalPrice(Double.parseDouble(finalPrice)*1000);
            cartService.save(cart);
        }
        else{
            cart.setId(cartId.intValue());
            cart.setTotalPrice(cart.getTotalPrice()+5);
            cartService.save(cart);
        }
        this.cartId = cartId;
        // Lấy người dùng từ cart
        Users user = cart.getUserId();

        Double totalPrice = cart.getTotalPrice();

        BigDecimal bigTotalPrice = new BigDecimal(cart.getTotalPrice()).setScale(2, RoundingMode.HALF_UP);



        if (payOption.equalsIgnoreCase("COD")) {
            orderService.orderCart(cartId, totalPrice, PayOption.COD, address);

            return "redirect:/order/success";
        } else if (payOption.equalsIgnoreCase("VNPAY")) {
            String vnp_Version = "2.1.0";
            String vnp_Command = "pay";
            String orderType = "other";
            String bankCode = "NCB";

            String vnp_TxnRef = com.shop.ecommerce.config.VNPayConfig.getRandomNumber(8);
            String vnp_IpAddr = "127.0.0.1";

            String vnp_TmnCode = com.shop.ecommerce.config.VNPayConfig.vnp_TmnCode;

            Map<String, String> vnp_Params = new HashMap<>();
            vnp_Params.put("vnp_Version", vnp_Version);
            vnp_Params.put("vnp_Command", vnp_Command);
            vnp_Params.put("vnp_TmnCode", vnp_TmnCode);

            long amountInCents = bigTotalPrice.multiply(BigDecimal.valueOf(100)).longValue();

            vnp_Params.put("vnp_Amount", String.valueOf(amountInCents));

            vnp_Params.put("vnp_CurrCode", "VND");

            vnp_Params.put("vnp_BankCode", bankCode);
            vnp_Params.put("vnp_TxnRef", vnp_TxnRef);
            vnp_Params.put("vnp_OrderInfo", "Thanh toan don hang:" + vnp_TxnRef);
            vnp_Params.put("vnp_OrderType", orderType);

            vnp_Params.put("vnp_Locale", "vn");
            vnp_Params.put("vnp_ReturnUrl", com.shop.ecommerce.config.VNPayConfig.vnp_ReturnUrl);
            vnp_Params.put("vnp_IpAddr", vnp_IpAddr);

            Calendar cld = Calendar.getInstance(TimeZone.getTimeZone("Etc/GMT+7"));
            SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
            String vnp_CreateDate = formatter.format(cld.getTime());
            vnp_Params.put("vnp_CreateDate", vnp_CreateDate);

            cld.add(Calendar.MINUTE, 15);
            String vnp_ExpireDate = formatter.format(cld.getTime());
            vnp_Params.put("vnp_ExpireDate", vnp_ExpireDate);

            List fieldNames = new ArrayList(vnp_Params.keySet());
            Collections.sort(fieldNames);
            StringBuilder hashData = new StringBuilder();
            StringBuilder query = new StringBuilder();
            Iterator itr = fieldNames.iterator();
            while (itr.hasNext()) {
                String fieldName = (String) itr.next();
                String fieldValue = (String) vnp_Params.get(fieldName);
                if ((fieldValue != null) && (fieldValue.length() > 0)) {
                    //Build hash data
                    hashData.append(fieldName);
                    hashData.append('=');
                    hashData.append(URLEncoder.encode(fieldValue, StandardCharsets.US_ASCII.toString()));
                    //Build query
                    query.append(URLEncoder.encode(fieldName, StandardCharsets.US_ASCII.toString()));
                    query.append('=');
                    query.append(URLEncoder.encode(fieldValue, StandardCharsets.US_ASCII.toString()));
                    if (itr.hasNext()) {
                        query.append('&');
                        hashData.append('&');
                    }
                }
            }
            String queryUrl = query.toString();
            String vnp_SecureHash = com.shop.ecommerce.config.VNPayConfig.hmacSHA512(com.shop.ecommerce.config.VNPayConfig.secretKey, hashData.toString());
            queryUrl += "&vnp_SecureHash=" + vnp_SecureHash;
            String paymentUrl = com.shop.ecommerce.config.VNPayConfig.vnp_PayUrl + "?" + queryUrl;
            System.out.println(paymentUrl);

            return "redirect:" + paymentUrl;
        } else {
            throw new RuntimeException("Invalid payment option");
        }
    }

    @GetMapping("/getPaymentInfo")
    public String getInfo(@RequestParam("vnp_TransactionNo") String transactionNo,
                          @RequestParam("vnp_OrderInfo") String orderInfo,
                          @RequestParam("vnp_TransactionStatus") String transactionStatus) {
        this.transactionStatus = transactionStatus;
        this.transactionNo = transactionNo;
        this.orderInfo = orderInfo;

        Cart cart = cartService.findById(this.cartId);

        Double totalPrice = cart.getTotalPrice();

        orderService.orderCart(cartId, totalPrice, PayOption.VNPAY, this.address);

        if(!Objects.equals(transactionNo, "0")) {
            this.orderSuccess = true;
        }
        else {
            this.orderSuccess = false;
        }
        return "redirect:/order/after-checkout";
    }
    @GetMapping("/after-checkout")
    public String after(Model model, HttpSession session) {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        Users user = (Users) session.getAttribute("user");

        model.addAttribute("email", email);
        model.addAttribute("orderSuccess", orderSuccess);
        model.addAttribute("transactionStatus", transactionStatus);
        model.addAttribute("transactionNo", transactionNo);
        model.addAttribute("orderInfo", orderInfo);
        model.addAttribute("customer", user);
        model.addAttribute("total", total);
        return "redirect:/";
    }

    @GetMapping("/success")
    public String sucess() {
        return "user/order-sucess";
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

        return "user/order-detail";
    }
}
