package com.example.spriingSecurity1.repository;

import com.example.spriingSecurity1.model.Contact;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ContactRepository extends CrudRepository<Contact, String> {


}
