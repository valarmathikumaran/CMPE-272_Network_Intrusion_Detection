"""parse credentials of database"""

from configparser import ConfigParser
#reads database parameters from database.ini file
def config(filename='database.ini', section='mysqlDB'):
    # create a parser
    parser = ConfigParser()
    # read config file
    parser.read(filename)

    # get section, default to mysql
    db = {}
    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            db[param[0]] = param[1]
    else:
        raise Exception('Section {0} not found in the {1} file'.format(section, filename))

    return db

