package hcmute.com.ShoeShop.repository;

import hcmute.com.ShoeShop.entity.ShippingCompany;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ShippingCompanyRepository extends JpaRepository<ShippingCompany, Integer> {
    public ShippingCompany findShippingCompanyById(int id);
}
