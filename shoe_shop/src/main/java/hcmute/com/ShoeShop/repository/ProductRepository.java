package hcmute.com.ShoeShop.repository;

import hcmute.com.ShoeShop.entity.Product;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
@SpringBootApplication
public interface ProductRepository extends JpaRepository<Product, Long> {
    Page<Product> findAllByCategoryId(Long categoryId, Pageable pageable);
    // list 20 san pham co avg rating cao nhat
    @Query("SELECT p FROM Product p JOIN p.ratings r GROUP BY p.id " +
            "ORDER BY (SUM(r.star) + 3 * 3.5) / (COUNT(r.star) + 3) DESC")
    List<Product> findTop20ByAvgRating();

    List<Product> findByCategoryId(Long categoryId);

    // tim kiem dua tren key word nhap vao
    Page<Product> findByTitleContainingIgnoreCase(String keyword, Pageable pageable);

    // tim kiem dua theo categoryID và keyword
    Page<Product> findByCategoryIdAndTitleContainingIgnoreCase(Long categoryId, String keyword, Pageable pageable);
}
