import requests
from requests.auth import HTTPDigestAuth
import json
import pandas as pd
from db_management import (User, Device, Vendor,
    Vulnerabilities, Refs, Base, Inventory)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def get_vendors():
    """ Runs an API call to the CVE online database to get a list of the 
    active vendors """
    url = "https://cve.circl.lu/api/browse"

    myResponse = requests.get(url, verify=True)

    if(myResponse.ok):
        
        vendors_df = pd.read_json(myResponse.content)
        vendor_df = vendors_df.drop('product', axis=1)
        vendor_df.rename(columns={'vendor':'name'}, inplace=True)
        vendor_data = df_dedupe(vendor_df, 'vendor', engine, dup_cols=['name'])
        vendor_data.to_sql('vendor', engine, if_exists='append', index=False)
        return vendor_data
    else:
        myResponse.raise_for_status()


def get_devices(vendor):
    """ Runs an API call to the CVE online database to get the active models
    for a vendor """
    url = "https://cve.circl.lu/api/browse/{}".format(vendor)

    myResponse = requests.get(url, verify=True)

    vendor_id = session.query(Vendor).filter(Vendor.name.startswith(vendor)).one().id

    if(myResponse.ok):
        device_df = pd.read_json(myResponse.content)
        device_df.rename(columns={'vendor':'name'}, inplace=True)
        device_data = df_dedupe(device_df, 'device', engine, dup_cols=['product'])
        device_data['vendor_id'] = vendor_id
        device_data.drop('name', axis=1, inplace=True)
        device_data.to_sql('device', engine, if_exists='append', index=False)
        return device_data
    else:
        myResponse.raise_for_status()


def df_dedupe(df, tablename, engine, dup_cols=[]):
    """
    Remove rows from a dataframe that already exist in a database
    Required:
        df : dataframe to remove duplicate rows from
        engine: SQLAlchemy engine object
        tablename: tablename to check duplicates in
        dup_cols: list or tuple of column names to check for duplicate row values
    Returns
        Unique list of values from dataframe compared to database table
    """
    args = 'SELECT %s FROM %s' %(', '.join(['"{0}"'.format(col) for col in dup_cols]), tablename)
    df = pd.merge(df, pd.read_sql(args, engine), how='left', on=dup_cols, indicator=True)
    df = df[df['_merge'] == 'left_only']
    df.drop(['_merge'], axis=1, inplace=True)
    return df

def build_refs(dataframe):
    refcolumns = ['id','references']
    ref = dataframe.loc[:, refcolumns]
    ref = list_to_dataframe(dataframe, refcolumns)
    ref.rename(columns={'id':'cve_id', 'references': 'url'}, inplace=True)
    ref_data = df_dedupe(ref, 'refs', engine, dup_cols=['cve_id'])
    ref_data.to_sql('refs', engine, if_exists='append', index=False)
    return ref_data


def get_vulnerability(vendor, device):
    """ Retrieves the active vulnerabilities for a particular device """
    url = "https://cve.circl.lu/api/search/{}/{}".format(vendor, device)

    myResponse = requests.get(url, verify=True)
    device_id = session.query(Device).filter(Device.product == device).one().id
    session.query(User).filter(User.id == 2)
    if(myResponse.ok):
        vulncolumns = ['id', 'cvss']
        df = pd.read_json(myResponse.content)
        vuln = df.loc[:, vulncolumns]
        vuln['device_id'] = device_id
        vuln.rename(columns={'id':'cve_id'}, inplace=True)
        vuln_data = df_dedupe(vuln, 'vulnerabilities', engine, dup_cols=['cve_id'])
        vuln_data.to_sql('vulnerabilities', engine, if_exists='append', index=False)
        build_refs(df)
        return vuln_data

    else:
        myResponse.raise_for_status()

def list_to_dataframe(dataframe, columns):
    result = dataframe.loc[:, columns]
    refs = result.references.apply(pd.Series)
    merged = refs.merge(result, left_index = True, right_index = True)
    pre_melt = merged.drop(["references"], axis = 1)
    melted = pre_melt.melt(id_vars = ['id'], value_name = "references")
    pre_na = melted.drop(['variable'], axis=1)
    final = pre_na.dropna()

    return final

def drop_tables():
    Base.metadata.drop_all(engine)

def add_device_to_inventory(device_id, user_id):
    new_dev = Inventory(device_id, user_id)
    session.add(new_dev)
    session.commit()

def add_user(username, password):
    new_user = User(username, password)
    session.add(new_user)
    session.commit()

#db.commit()
engine = create_engine('sqlite:///vuln.db')
#drop_tables()
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
vendor_list = get_vendors()
device_list = get_devices('microsoft')
vuln_list = get_vulnerability('microsoft','windows_10')

vendors = ['cisco','microsoft','']
devices = ['windows_7','windows_10','']
#build_references(vuln_list)
#data = populate_vendors(db)
#print df
