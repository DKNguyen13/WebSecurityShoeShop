package hcmute.com.ShoeShop.repository;

import hcmute.com.ShoeShop.entity.Cart;
import hcmute.com.ShoeShop.entity.CartDetail;
import hcmute.com.ShoeShop.entity.ProductDetail;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CartDetailRepository extends JpaRepository<CartDetail, Long> {
    Optional<CartDetail> findByCartAndProduct(Cart cart, ProductDetail productDetail);
}
