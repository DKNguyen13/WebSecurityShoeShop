package hcmute.com.ShoeShop.repository;

import hcmute.com.ShoeShop.entity.Order;
import hcmute.com.ShoeShop.utlis.ShipmentStatus;
import org.aspectj.weaver.ast.Or;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Repository
public interface OrderRepository extends JpaRepository<Order, Integer> {
//        @Query("select o, s.status from Order o join Shipment s on s.order.id = o.id")
//        public List<Object> findALlWithStatus();

        public Order findOrderById(int orderId);

        long countByStatus(ShipmentStatus status);

        public Page<Order> findOrderByStatus(ShipmentStatus status, Pageable pageable);

        public Page<Order> findOrderByUser_Id(int userId, Pageable pageable);

        @Query("SELECT COUNT(od) > 0 FROM OrderDetail od JOIN od.order o WHERE o.user.id = :userId AND od.product.product.id = :productId AND o.status = 'DELIVERED'")
        boolean existsByUser(long userId, long productId);
        @Query("select sum(o.totalPrice) from Order o where o.status = 'DELIVERED'")
        public Optional<Double> sumTotalPrice();
        @Query("select sum(o.totalPrice) from Order o where o.status = 'DELIVERED' and o.createdDate BETWEEN :startDate AND :endDate")
        public Optional<Double> sumTotalPriceByDate(Date startDate, Date endDate);

        public int countByCreatedDateBetween(Date startDate, Date endDate);
}
