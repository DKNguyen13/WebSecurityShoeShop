package hcmute.com.ShoeShop.services.imp;

import hcmute.com.ShoeShop.dto.OrderStaticDto;
import hcmute.com.ShoeShop.entity.Cart;
import hcmute.com.ShoeShop.entity.Order;
import hcmute.com.ShoeShop.entity.OrderDetail;
import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.repository.CartRepository;
import hcmute.com.ShoeShop.repository.OrderRepository;
import hcmute.com.ShoeShop.services.IOrderService;
import hcmute.com.ShoeShop.utlis.PayOption;
import hcmute.com.ShoeShop.utlis.ShipmentStatus;
import org.aspectj.weaver.ast.Or;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class OrderServiceImpl implements IOrderService {
        @Autowired
        OrderRepository orderRepository;
        @Autowired
        CartRepository cartRepository;

        public Page<Order> findAll(Pageable pageable) {
                return orderRepository.findAll(pageable);
        }

        public Order findById(int orderId) {
                return orderRepository.findById(orderId).orElseThrow(() -> new RuntimeException("can not find order"));
        }

        public void cancelOrder(int orderId) {
                Order order = findById(orderId);
                order.setStatus(ShipmentStatus.CANCEL);
                orderRepository.save(order);
        }

        public OrderStaticDto getStatic(){
                OrderStaticDto orderStaticDto = new OrderStaticDto();
                orderStaticDto.setShipping(orderRepository.countByStatus(ShipmentStatus.SHIPPED));
                orderStaticDto.setCancel(orderRepository.countByStatus(ShipmentStatus.CANCEL));
                orderStaticDto.setInStock(orderRepository.countByStatus(ShipmentStatus.IN_STOCK));
                orderStaticDto.setPreturn(orderRepository.countByStatus(ShipmentStatus.RETURN));
                orderStaticDto.setDelivered(orderRepository.countByStatus(ShipmentStatus.DELIVERED));

                return orderStaticDto;
        }

        public OrderStaticDto getStatic(List<Order> orders) {
                OrderStaticDto orderStaticDto = new OrderStaticDto();
                orderStaticDto.setShipping(orders.stream().filter(order -> order.getStatus() == ShipmentStatus.SHIPPED).count());
                orderStaticDto.setCancel(orders.stream().filter(order -> order.getStatus() == ShipmentStatus.CANCEL).count());
                orderStaticDto.setInStock(orders.stream().filter(order -> order.getStatus() == ShipmentStatus.IN_STOCK).count());
                orderStaticDto.setPreturn(orders.stream().filter(order -> order.getStatus() == ShipmentStatus.RETURN).count());
                orderStaticDto.setDelivered(orders.stream().filter(order -> order.getStatus() == ShipmentStatus.DELIVERED).count());
                return orderStaticDto;
        }

        public void deliverOrder(int orderId) {
                Order order = findById(orderId);
                order.setStatus(ShipmentStatus.DELIVERED);
                orderRepository.save(order);
        }

        public void returnOrder(int orderId) {
                Order order = findById(orderId);
                order.setStatus(ShipmentStatus.RETURN);
                orderRepository.save(order);
        }

        public Page<Order> findOrderByStatus(ShipmentStatus shipmentStatus, Pageable pageable) {
                return orderRepository.findOrderByStatus(shipmentStatus, pageable);
        }
        public Page<Order> findOrderByUserId(int usreId, Pageable pageable) {
                return orderRepository.findOrderByUser_Id(usreId, pageable);
        }

        public void orderCart(Long cartId, double price, PayOption payOption, String address){
                Cart cart = cartRepository.findCartsById(cartId);
                Order order = Order.builder()
                        .user(cart.getUserId())
                        .totalPrice(price)
                        .createdDate(new Date())
                        .payOption(payOption)
                        .address(address)
                        .status(ShipmentStatus.IN_STOCK)
                        .build();
                Set<OrderDetail> orderDetails = new HashSet<>();
                for (var cartItem: cart.getOrderDetailSet()){
                        OrderDetail orderDetail = OrderDetail.builder()
                                .order(order)
                                .product(cartItem.getProduct())
                                .quantity(cartItem.getQuantity())
                                .price(cartItem.getPrice())
                                .build();

                        orderDetails.add(orderDetail);
                }

                order.setOrderDetailSet(orderDetails);

                orderRepository.save(order);
                cartRepository.delete(cart);
        }

        public boolean checkOrderByUser(Users user, long productId) {
                return orderRepository.existsByUser(user.getId(), productId);
        }
        public long countOrder(){
                return orderRepository.count();
        }

        public Optional<Double> totalPrice(){
                return orderRepository.sumTotalPrice();
        }

        public void save(Order order) {
                orderRepository.save(order);
        }

        public int orderCountByDate(Date startDate, Date endDate) {
                return orderRepository.countByCreatedDateBetween(startDate, endDate);
        }

        public double totalPriceByDate(Date startDate, Date endDate) {
                return orderRepository.sumTotalPriceByDate(startDate, endDate).orElse(0.0);
        }
}
