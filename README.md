# is211_finalproject

This is the portion of the final project which has the database, api structure intact.

get_vendors() builds a list of vendors by accessing the API at https://cve.circl.lu this is run initially to build out the vendor DB
get_devices(vendor) does a search of the API for devices from a particular vendor, takes the JSON return data, and puts that into a pandas dataframe.  After some data manipulation, the data in the dataframe is compared to the database data, and any non duplicate items are inserted into the DB
get_vulnerability(vendor, device) gets the vulnerability data from a tuple of vendor, device.  The references data is a list of websites, which was difficult to pull out of the json data without heavy manipulation.  The use of pandas warp was able to get this function to work without significant time spent in loops.
