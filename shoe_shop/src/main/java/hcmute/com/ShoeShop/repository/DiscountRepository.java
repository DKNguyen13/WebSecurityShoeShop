package hcmute.com.ShoeShop.repository;

import hcmute.com.ShoeShop.entity.Discount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DiscountRepository extends JpaRepository<Discount, Integer> {
    Discount findById(int id);
}
