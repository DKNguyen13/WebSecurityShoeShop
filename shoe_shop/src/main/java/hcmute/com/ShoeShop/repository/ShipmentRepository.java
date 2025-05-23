package hcmute.com.ShoeShop.repository;

import hcmute.com.ShoeShop.entity.Shipment;
import hcmute.com.ShoeShop.utlis.ShipmentStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ShipmentRepository extends JpaRepository<Shipment, Long> {
        public Shipment findShipmentById(int id);
        public Shipment findShipmentByOrderId(int orderId);
        public Page<Shipment> findShipmentByShipper_Id(int userId, Pageable pageable);
        public Page<Shipment> findByShipper_IdAndOrder_Status(int userId, ShipmentStatus shipmentStatus, Pageable pageable);
        public List<Shipment> findShipmentByShipper_Id(int userID);
}
