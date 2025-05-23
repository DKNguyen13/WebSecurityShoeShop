package hcmute.com.ShoeShop.services.imp;

import hcmute.com.ShoeShop.entity.Order;
import hcmute.com.ShoeShop.entity.Shipment;
import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.repository.OrderRepository;
import hcmute.com.ShoeShop.repository.ShipmentRepository;
import hcmute.com.ShoeShop.repository.UserRepository;
import hcmute.com.ShoeShop.utlis.ShipmentStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Service
public class ShipmentService {
        @Autowired
        ShipmentRepository shipmentRepository;
        @Autowired
        OrderRepository orderRepository;
        @Autowired
        UserRepository userRepository;
        public Shipment findShipmentByOrderId(int orderId){
                return shipmentRepository.findShipmentByOrderId(orderId);
        }

        public void insertShipment(int orderid, int userid) {
                Shipment shipment = new Shipment();

                Order order = orderRepository.findOrderById(orderid);
                Users user = userRepository.findUsersById(userid);

                shipment.setOrder(order);
                shipment.setShipper(user);
                shipment.setNote("");
                shipment.setUpdatedDate(new Date());
                shipmentRepository.save(shipment);

                order.setStatus(ShipmentStatus.SHIPPED);

                orderRepository.save(order);
        }

        public Page<Shipment> findByShipperID(int userid, Pageable pageable) {
                return shipmentRepository.findShipmentByShipper_Id(userid, pageable);
        }

        public void updateDate(int orderId){
                Shipment shipment = findShipmentByOrderId(orderId);
                shipment.setUpdatedDate(new Date());

                shipmentRepository.save(shipment);
        }

        public void updateNote(int shipmentId, String note){
                Shipment shipment = shipmentRepository.findShipmentById(shipmentId);
                shipment.setNote(note);
                shipmentRepository.save(shipment);
        }

        public Page<Shipment> findByShipperIdAndStatus(int userid, ShipmentStatus shipmentStatus, Pageable pageable) {
                return shipmentRepository.findByShipper_IdAndOrder_Status(userid, shipmentStatus, pageable);
        }

        public List<Shipment> findByShipperId(int userid) {
                return shipmentRepository.findShipmentByShipper_Id(userid);
        }
}
