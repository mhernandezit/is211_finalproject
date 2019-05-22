import os
import sys
import pandas
from sqlalchemy import Column, ForeignKey, Integer, String, Numeric, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref, scoped_session, sessionmaker
from sqlalchemy import create_engine
from werkzeug.security import generate_password_hash, check_password_hash
from database import Base


class User(Base):
    """An admin user capable of viewing reports.

    :param str email: email address of user
    :param str password: encrypted password for the user

    """
    __tablename__ = 'user'
    id = Column(Integer, primary_key = True)
    name = Column(String(30))
    password_hash = Column(String(25))

    def get_id(self):
        try:
            return (self.id)
        except AttributeError:
            raise NotImplementedError('No `id` attribute - override `get_id`')

    @property
    def password(self):
        raise AttributeError('password is not readable')
    
    @password.setter
    def password(self,password):
        self.password_hash = generate_password_hash(password)

    @password.getter
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        """True, as all users are active."""
        return True

    @property
    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    @property
    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False

    def get_name(self):
        return self.name

class Vendor(Base):
    __tablename__ = 'vendor'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False, unique=True)
    
class Device(Base):
    __tablename__ = 'device'
    id = Column(Integer, primary_key=True)
    product = Column(String(250), nullable=False, unique=True)
    vendor_id = Column(Integer, ForeignKey('vendor.id'))
    owner_id = Column(Integer, ForeignKey('user.id'))
    owner = relationship(User, backref=backref('devices'), uselist=True)

class Inventory(Base):
    __tablename__ = 'inventory_link'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    device_id = Column(Integer, ForeignKey('device.id'))

class Refs(Base):
    __tablename__ = 'refs'
    id = Column(Integer, primary_key=True)
    cve_id = Column(String(15), ForeignKey('vulnerabilities.cve_id'))
    url = Column(String(250), nullable=True)

class Vulnerabilities(Base):
    __tablename__ = 'vulnerabilities'
    id = Column(Integer, primary_key=True)
    cve_id = Column(String(15))
    cvss = Column(Integer)
    device_id = Column(Integer, ForeignKey('device.id'))

