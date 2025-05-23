package hcmute.com.ShoeShop.dto;

import hcmute.com.ShoeShop.entity.Product;
import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.util.Set;

@Data
public class CategoryDto {
    protected Long id;
    private String type;
    private String description;
}
