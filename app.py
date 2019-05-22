import requests
from requests.auth import HTTPDigestAuth
import json
import os
import pandas as pd
from models import (User, Device, Vendor,
    Vulnerabilities, Refs, Base, Inventory)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from flask import (Flask, render_template, request, redirect,
                   g, flash, url_for, abort)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from flask_login import login_user, logout_user, login_required, \
    current_user, LoginManager
from flask_bootstrap import Bootstrap
from werkzeug.security import check_password_hash, generate_password_hash
from models import db_session, engine, init_db

# Global Configurations
app = Flask(__name__)
bootstrap = Bootstrap(app)
login_manager = LoginManager()
app.secret_key = os.urandom(24).encode('hex')
login_manager.init_app(app)
init_db()

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()

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

    else:
        myResponse.raise_for_status()


def get_devices(vendor):
    """ Runs an API call to the CVE online database to get the active models
    for a vendor """
    url = "https://cve.circl.lu/api/browse/{}".format(vendor)

    myResponse = requests.get(url, verify=True)

    vendor_id = Vendor.query(Vendor.name == vendor).
    db_session.query(Vendor).filter(Vendor.name.startswith(vendor)).one().id

    if(myResponse.ok):
        device_df = pd.read_json(myResponse.content)
        device_df.rename(columns={'vendor':'name'}, inplace=True)
        device_data = df_dedupe(device_df, 'device', engine, dup_cols=['product'])
        device_data['vendor_id'] = vendor_id
        device_data.drop('name', axis=1, inplace=True)
        device_data.to_sql('device', engine, if_exists='append', index=False)
        device_dict = device_data.to_dict()
        return device_dict
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
    """ Builds out the references column """
    refcolumns = ['id','references']
    ref = dataframe.loc[:, refcolumns]
    ref = list_to_dataframe(dataframe, refcolumns)
    ref.rename(columns={'id':'cve_id', 'references': 'url'}, inplace=True)
    ref_data = df_dedupe(ref, 'refs', engine, dup_cols=['cve_id'])
    ref_data.to_sql('refs', engine, if_exists='append', index=False)
    ref_dict = ref_data.to_dict()

def get_vulnerability(vendor, device):
    """ Retrieves the active vulnerabilities for a particular device """
    url = "https://cve.circl.lu/api/search/{}/{}".format(vendor, device)

    myResponse = requests.get(url, verify=True)
    device_id = db_session.query(Device).filter(Device.product == device).one().id
    
    if(myResponse.ok):
        vulncolumns = ['id', 'cvss']
        df = pd.read_json(myResponse.content)
        vuln = df.loc[:, vulncolumns]
        vuln['device_id'] = device_id
        vuln.rename(columns={'id':'cve_id'}, inplace=True)
        vuln_data = df_dedupe(vuln, 'vulnerabilities', engine, dup_cols=['cve_id'])
        vuln_data.to_sql('vulnerabilities', engine, if_exists='append', index=False)
        build_refs(df)
        vuln_dict = vuln_data.to_dict()
        return vuln_dict

    else:
        myResponse.raise_for_status()

def list_to_dataframe(dataframe, columns):
    """ Helper function for the references table - multistep pandas process to 
    unwind the list column, and merge it with the original table to create a
    flat database structure """
    result = dataframe.loc[:, columns]
    refs = result.references.apply(pd.Series)
    merged = refs.merge(result, left_index = True, right_index = True)
    pre_melt = merged.drop(["references"], axis = 1)
    melted = pre_melt.melt(id_vars = ['id'], value_name = "references")
    pre_na = melted.drop(['variable'], axis=1)
    final = pre_na.dropna()
    return final

def drop_tables():
    """ Helper function to drop all database tables """
    Base.metadata.drop_all(engine)

def add_device_to_inventory(product, vendor_id):
    """ Adds a new device to the current owner's inventory """
    device = Device(owner=[db_session.test], product=product, vendor_id=vendor_id)
    db_session.add(device)
    db_session.commit()

def get_inventory(user_id):
    """ Returns all devices that currently belong to the currently
    logged in user"""
    db_session.query(Inventory)

def add_user(user):
    """ Creates a new user, adds it to the database
    returns user object """
    if User.query.filter(User.name == user.name).first():
        pass
    else:
        db_session.add(user)
        db_session.commit()
        return user


def initialize_db():
    get_vendors()
    data_to_load = {'microsoft': ['windows_10','windows_7'],
                    'cisco': ['asr_1002-x']}

    for vendor, products in data_to_load.items():
        get_devices(vendor)
        for product in products:
            get_vulnerability(vendor, product)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

class LoginForm(FlaskForm):
    name = StringField('Username', validators=[Required()])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Log In')

class AddDeviceForm(FlaskForm):
    device = StringField('device')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User(form.name, form.password)
        login_user(user)

        flash('Logged in successfully.')

        next = request.args.get('next')
        if not is_safe_url(next):
            return abort(400)

        return redirect(next or url_for('index'))
    return render_template('auth/login.html', form=form)

@app.route("/", methods=['GET', 'POST'])
@login_required
def index():
    form = AddDeviceForm()
    user = g.current_user
    return render_template('dashboard.html', user=user)

@app.route('/inventory')
@login_required
def inventory():
    page = request.args.get('page', 1, type=int)
    pagination = user.inventory.order_by(Device.product.desc()).paginate(
        page, per_page=25, error_out=False)
    devices = pagination.items
    return render_template('inventory.html', user=current_user.__name__, devices=devices,
                           pagination=pagination)

@app.route('/add/<device>', methods = ['GET', 'POST'])
@login_required
def add_device(device):
    user = User.query.filter_by()


def init():
    initialize_db()


if __name__ == '__main__':
    init()
    user = User("admin","password")
    add_user(user)
    login_user(user)
    add_device_to_inventory("")
    app.run(debug=1)

# for (key, value) in device_list.items():
#     print "{} :: {}".format(key, value)

# for (key, value) in vuln_list.items():
#     print "{} :: {}".format(key, value)


#device = Device(owner=[test], product='.net_core', vendor_id='3188')

#db_session.add(device)

#build_references(vuln_list)
#data = populate_vendors(db)
#print df

# add_device_to_inventory('microsoft','windows_10')
# add_device_to_inventory('cisco', '881_integrated_services_router')

