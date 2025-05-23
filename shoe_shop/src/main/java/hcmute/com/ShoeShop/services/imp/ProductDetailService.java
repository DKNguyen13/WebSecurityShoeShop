package hcmute.com.ShoeShop.services.imp;

import hcmute.com.ShoeShop.entity.Product;
import hcmute.com.ShoeShop.entity.ProductDetail;
import hcmute.com.ShoeShop.repository.ProductDetailRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class ProductDetailService {

    @Autowired
    @Lazy

    private ProductService productService;

    @Autowired
    private ProductDetailRepository productDetailRepository;


    public List<ProductDetail> findProductByProductId(long productId) {
        List<ProductDetail> productDetails = productDetailRepository.findByProductId(productId);
        return productDetails;
    }

    public void save(ProductDetail productDetail) {
        productDetailRepository.save(productDetail);
    }
    public Optional<ProductDetail> findProductDetailById(long productDetailId) {
        return productDetailRepository.findById(productDetailId);
    }


    public ProductDetail findByProductAndSize(Product product, int size) {
        return productDetailRepository.findByProductAndSize(product, size);
    }
}
