package hcmute.com.ShoeShop.services.imp;

import hcmute.com.ShoeShop.entity.ShippingCompany;
import hcmute.com.ShoeShop.repository.ShippingCompanyRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class ShippingCompanyService {
    @Autowired
    ShippingCompanyRepository shippingCompanyRepository;

    public List<ShippingCompany> findAll(){
       return shippingCompanyRepository.findAll();
    }

    public void saveSC(ShippingCompany sc){
        shippingCompanyRepository.save(sc);
    }

    public void changStatus(ShippingCompany sc){
        if(sc.getActive()){
            sc.setActive(false);
        }
        else
            sc.setActive(true);
        shippingCompanyRepository.save(sc);
    }

    public ShippingCompany findShippingCompanyById(int id){
        return shippingCompanyRepository.findShippingCompanyById(id);
    }

    public Page<ShippingCompany> findAll(Pageable pageable) {
        return shippingCompanyRepository.findAll(pageable);
    }

    public List<ShippingCompany> findShippingCompaniesActive(){
        List<ShippingCompany> scs = findAll();
        List<ShippingCompany> scsActive = new ArrayList<>();
        for(ShippingCompany sc : scs){
            if(sc.getActive()){
                scsActive.add(sc);
            }
        }
        return scsActive;
    }
}
