package hcmute.com.ShoeShop.repository;

import hcmute.com.ShoeShop.entity.Cart;
import hcmute.com.ShoeShop.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CartRepository extends JpaRepository<Cart, Long> {
    Optional<Cart> findByUserId(Users user);

    @Query("SELECT c FROM Cart c WHERE c.userId.email = :email")
    Optional<Cart> findByEmail(@Param("email") String email);

    Cart findCartsById(long cartId);
}
