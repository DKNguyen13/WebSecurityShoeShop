package hcmute.com.ShoeShop.dto;
import lombok.Data;

import java.util.List;

@Data
public class ProductDto {

    protected Long id;
    protected Long categoryId;

    private String title;

    private String description;
    private Long voucher;

    private double price;

    private String categoryName;
    private List<ProductDetailDto> productDetails;
}
