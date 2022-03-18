from os import environ

# ignore local configs during test run
environ['TRACKER_CONFIG_LOCAL'] = 'false'
