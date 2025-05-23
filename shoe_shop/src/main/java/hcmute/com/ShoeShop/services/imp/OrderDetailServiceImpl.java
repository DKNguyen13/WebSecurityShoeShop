package hcmute.com.ShoeShop.services.imp;

import hcmute.com.ShoeShop.dto.OrderDetailDto;
import hcmute.com.ShoeShop.dto.OrderPaymentDto;
import hcmute.com.ShoeShop.entity.Order;
import hcmute.com.ShoeShop.entity.OrderDetail;
import hcmute.com.ShoeShop.repository.OrderDetailRepository;
import hcmute.com.ShoeShop.repository.OrderRepository;
import hcmute.com.ShoeShop.services.IOrderDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class OrderDetailServiceImpl implements IOrderDetailService {
        @Autowired
        OrderDetailRepository orderDetailRepository;

        @Autowired
        OrderRepository orderRepository;

        public List<OrderDetailDto> findAllOrderDetailById(int orderId){
                List<OrderDetail> optionalOrderDetail = orderDetailRepository.findOrderDetailsByOrderId(orderId);

                List<OrderDetailDto> listDetailRes = new ArrayList<>();
                for (var item: optionalOrderDetail.stream().toList()){
                        OrderDetailDto detailDto = new OrderDetailDto();
                        //map data from OrderDetail to OrderDetailDTO
                        detailDto.setSize(item.getProduct().getSize());
                        detailDto.setProduct_name(item.getProduct().getProduct().getTitle());
                        detailDto.setImage(item.getProduct().getProduct().getImage());
                        detailDto.setPrice(item.getPrice());
                        detailDto.setQuantity(item.getQuantity());
                        detailDto.setAmount(item.getPrice() * item.getQuantity());

                        listDetailRes.add(detailDto);
                }
                return listDetailRes;
        }

        public OrderPaymentDto getOrderPayment(int orderId){
                List<OrderDetail> optionalOrderDetail = orderDetailRepository.findOrderDetailsByOrderId(orderId);
                OrderPaymentDto orderPaymentDto = new OrderPaymentDto();
                double total = 0, discount = 0, payment = 0;
                for (var item: optionalOrderDetail.stream().toList()){
                        total += (item.getProduct().getPriceadd() + item.getProduct().getProduct().getPrice()) * item.getQuantity();
                }
                total += 5;
                Order order = orderRepository.findOrderById(orderId);
                payment = order.getTotalPrice();
                discount = total - payment;


                orderPaymentDto.setDiscount(discount);
                orderPaymentDto.setTotalpay(payment);
                orderPaymentDto.setSubtotal(total);
                return orderPaymentDto;
        }

}
