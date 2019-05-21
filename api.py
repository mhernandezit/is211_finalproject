import requests
from requests.auth import HTTPDigestAuth
import json
import pandas as pd
from db_management import (User, Device, Vendor,
    Vulnerabilities, References, Base, Inventory)
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
        append_data = df_dedupe(vendor_df, 'vendor', engine, dup_cols=['name'])
        append_data.to_sql('vendor', engine, if_exists='append', index=False)
        return vendor_df
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
        append_data = df_dedupe(device_df, 'device', engine, dup_cols=['product'])
        append_data['vendor_id'] = vendor_id
        append_data.drop('name', axis=1, inplace=True)
        append_data.to_sql('device', engine, if_exists='append', index=False)
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

def build_references(dataframe):
    refcolumns = ['id','references']
    ref = list_to_dataframe(dataframe, refcolumns)
    ref.rename(columns={'id':'cve_id', 'references': 'url'}, inplace=True)
    append_data = df_dedupe(ref, 'references', engine, dup_cols=['url'])
    append_data.to_sql('references', engine, if_exists='append', index=False)


def get_vulnerability(vendor, device):
    """ Retrieves the active vulnerabilities for a particular device """
    url = "https://cve.circl.lu/api/search/{}/{}".format(vendor, device)

    myResponse = requests.get(url, verify=True)
    vendor_id = session.query(Vendor).filter(Vendor.name.startswith(vendor)).one().id
    device_id = session.query(Device).filter(Device.product.startswith(device)).one().id

    if(myResponse.ok):
        vulncolumns = ['id', 'cvss']
        df = pd.read_json(myResponse.content)

        vuln = df.loc[:, vulncolumns]
        vuln['device_id'] = device_id
        vuln.rename(columns={'id':'cve_id'}, inplace=True)
        vuln.to_sql('vulnerabilities', engine, if_exists='append', index=False)

    else:
        myResponse.raise_for_status()

def list_to_dataframe(dataframe, columns):
    result = dataframe.loc[:, columns]
    references = result.references.apply(pd.Series)
    merged = references.merge(result, left_index = True, right_index = True)
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
# drop_tables()
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
get_vendors()
get_devices('cisco')
get_vulnerability('cisco','3660_router')
#data = populate_vendors(db)
#print df
