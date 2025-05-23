package hcmute.com.ShoeShop.repository;

import hcmute.com.ShoeShop.entity.Product;
import hcmute.com.ShoeShop.entity.Rating;
import hcmute.com.ShoeShop.entity.Users;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RatingRepository extends JpaRepository<Rating, Long> {
    @Query("SELECT r FROM Rating r WHERE r.product.id = :productId")
    List<Rating> findAllByProductId(long productId);

    Rating findByUserAndProduct(Users user, Product product);

    Rating findByUser(Users user);

    List<Rating> findAllByUser(Users user);

    Page<Rating> findAllByProductId(long productId, Pageable pageable);

    int countRatingByProductId(long productId);
}
