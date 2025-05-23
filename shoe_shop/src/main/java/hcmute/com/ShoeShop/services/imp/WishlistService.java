package hcmute.com.ShoeShop.services.imp;

import hcmute.com.ShoeShop.entity.Product;
import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.entity.WishList;
import hcmute.com.ShoeShop.repository.ProductRepository;
import hcmute.com.ShoeShop.repository.UserRepository;
import hcmute.com.ShoeShop.repository.WishlistRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class WishlistService {

    @Autowired
    private WishlistRepository wishListRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ProductRepository productRepository;

    public void save(WishList wishList) {
        wishListRepository.save(wishList);
    }

    public void delete(WishList wishList) {
        wishListRepository.delete(wishList);
    }

    public boolean addToWishlist(int userId, long productId) {
        Users user = userRepository.findById(userId).orElse(null);
        Product product = productRepository.getReferenceById(productId);

        if (user != null && product != null) {
            WishList wishList = new WishList();
            wishList.setUser(user);
            wishList.setProduct(product);
            wishListRepository.save(wishList);
            return true;
        }
       return false;
    }

    public boolean toggleWishlist(int userId, long productId) {
        // Tìm user và product từ cơ sở dữ liệu
        Users user = userRepository.findById(userId).orElse(null);
        Product product = productRepository.findById(productId).orElse(null);

        if (user == null || product == null) {
            // Nếu không tìm thấy user hoặc product, không làm gì cả
            return false;
        }

        // Kiểm tra xem sản phẩm có tồn tại trong wishlist không
        WishList existingWishList = wishListRepository.findByUserAndProduct(user, product);

        if (existingWishList != null) {
            // Nếu tồn tại, xóa sản phẩm khỏi wishlist
            wishListRepository.delete(existingWishList);
            return false; // Trả về false nếu sản phẩm đã bị xóa
        } else {
            // Nếu chưa tồn tại, thêm sản phẩm vào wishlist
            WishList newWishList = new WishList();
            newWishList.setUser(user);
            newWishList.setProduct(product);
            wishListRepository.save(newWishList);
            return true; // Trả về true nếu sản phẩm đã được thêm
        }
    }

    public WishList findByUserAndProduct(int userId, long productId) {
        // Tìm user và product
        Users user = userRepository.findById(userId).orElse(null);
        Product product = productRepository.findById(productId).orElse(null);

        // Trả về null nếu không tìm thấy
        if (user == null || product == null) {
            return null;
        }

        // Truy vấn từ wishlist
        return wishListRepository.findByUserAndProduct(user, product);
    }
    public List<Product> getWishlist(int userId) {
        // Lấy danh sách các WishList của người dùng
        List<WishList> wishLists = wishListRepository.findWishListByUserId(userId);

        List<Product> products = new ArrayList<>();
        for (WishList item : wishLists) {
            products.add(item.getProduct()); // Thêm sản phẩm vào danh sách
        }
        return products;
    }

    public boolean deleteProductFromWishlist(int userId, long productId) {
        // Lấy người dùng và sản phẩm từ cơ sở dữ liệu
        Users user = userRepository.findById(userId).orElse(null);
        Product product = productRepository.findById(productId).orElse(null);

        if (user == null || product == null) {
            System.out.println("User or Product not found");
            return false; // Nếu không tìm thấy người dùng hoặc sản phẩm
        }

        // Tìm wishlist của người dùng với sản phẩm này
        WishList wishList = wishListRepository.findByUserAndProduct(user, product);
        if (wishList != null) {
            wishListRepository.delete(wishList);
            return true; // Xóa thành công
        }
        System.out.println("Product not found in wishlist for user");
        return false; // Không tìm thấy sản phẩm trong wishlist
    }

    void deleteByProductId(Long productId){
        wishListRepository.deleteByProductId(productId);
    }
}
