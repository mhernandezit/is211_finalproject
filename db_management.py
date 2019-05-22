import os
import sys
import pandas
from sqlalchemy import Column, ForeignKey, Integer, String, Numeric
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
 
Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False, unique=True)
    password = Column(String(20), nullable=False)

class Vendor(Base):
    __tablename__ = 'vendor'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False, unique=True)
    
class Device(Base):
    __tablename__ = 'device'
    id = Column(Integer, primary_key=True)
    product = Column(String(250), nullable=False, unique=True)
    vendor_id = Column(Integer, ForeignKey('vendor.id'))
    vendor = relationship("Vendor")

class Inventory(Base):
    __tablename__ = 'inventory'
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

# Create an engine that stores data in the local directory's
# sqlalchemy_example.db file.
engine = create_engine('sqlite:///vuln.db')
 
# Create all tables in the engine. This is equivalent to "Create Table"
# statements in raw SQL.
Base.metadata.create_all(engine)