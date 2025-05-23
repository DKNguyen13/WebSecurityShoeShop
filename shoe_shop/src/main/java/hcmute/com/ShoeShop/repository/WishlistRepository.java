package hcmute.com.ShoeShop.repository;

import hcmute.com.ShoeShop.entity.Product;
import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.entity.WishList;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface WishlistRepository extends JpaRepository<WishList, Integer> {
    WishList findByUserAndProduct(Users user, Product product);
    List<WishList> findWishListByUserId(int userId);
    void deleteByProductId(Long productId);

}
