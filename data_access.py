import sqlite3
import logging
from datetime import datetime
from errors import TransactionError

con = sqlite3.connect('task.sqlite', check_same_thread=False)
con.row_factory = sqlite3.Row
cur = con.cursor()

table_creation_queries = [ 
    'CREATE TABLE IF NOT EXISTS requests(request_id text PRIMARY KEY, domain text, status text, requested_at text);',
    'CREATE TABLE IF NOT EXISTS servers(server_id integer PRIMARY KEY AUTOINCREMENT, request_id text, server text, country text, region text, last_updated text);',
    'CREATE TABLE IF NOT EXISTS users(user_id integer PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL)'
    ]

## Creation of the tables if they do not exist
def create_tables():
    logging.info('Generating tables if not existing')
    for table_query in table_creation_queries:
        try:
            cur.execute(table_query)
            con.commit()
        except Exception as err:
            logging.error(f'Generation of tables in database failed with error - {str(err)}')
            raise TransactionError(f'Generation of tables in database failed')

## Adding a new user to the db
async def add_user(username, password):
    try:
        cur.execute('INSERT INTO users(username, password) VALUES (?, ?);', (username, password))
        con.commit()
        
    except (sqlite3.OperationalError, sqlite3.DataError) as err:
        logging.error('registering new user failed because of wrong data')
        raise TransactionError('registering new user failed because of wrong data')
    
    except Exception as err:
        logging.error(f'registering new user in database failed with error - {str(err)}')
        raise TransactionError('registering new user in database failed')

## Adding a new domain to the db with the uuid generated as an id
async def add_domain(request_id, domain):
    try:
        cur.execute('INSERT INTO requests(request_id, domain, status, requested_at) VALUES (?, ?, ?, ?);', (request_id, domain, 'Resolving Servers', datetime.now().isoformat()))
        con.commit()
        
    except (sqlite3.OperationalError, sqlite3.DataError) as err:
        logging.error('Adding request failed because of wrong data')
        raise TransactionError('Adding request failed because of wrong data')
    
    except Exception as err:
        logging.error(f'Adding request in database failed with error - {str(err)}')
        raise TransactionError('Adding request in database failed')

## Adding a new server to the db
async def add_server(request_id, server):
    try:
        cur.execute('INSERT INTO servers(request_id, server, last_updated) VALUES (?, ?, ?);', (request_id, server, datetime.now().isoformat()))
        con.commit()
        
    except (sqlite3.OperationalError, sqlite3.DataError) as err:
        logging.error('Adding server failed because of wrong data')
        raise TransactionError('Adding server failed because of wrong data')
    
    except Exception as err:
        logging.error(f'Adding server in database failed with error - {str(err)}')
        raise TransactionError(f'Adding server in database failed')

## Changing request status in the db
async def set_request_status(request_id, status):
    try:
        cur.execute('UPDATE requests SET status = ? WHERE request_id = ?;', (status, request_id))
        con.commit()
        
    except (sqlite3.OperationalError, sqlite3.DataError) as err:
        logging.error('Status change failed because of wrong data')
        raise TransactionError('Status change failed because of wrong data')
    
    except Exception as err:
        logging.error(f'Request status change in database failed with error - {str(err)}')
        raise TransactionError(f'Request status change in database failed')

## Changing the server location in the db
async def set_server_location(country, region, request_id, server):
    try:
        cur.execute('UPDATE servers SET country = ?, region = ?, last_updated = ? WHERE request_id = ? and server = ?;', (country, region, datetime.now().isoformat(), request_id, server))
        con.commit()
        
    except (sqlite3.OperationalError, sqlite3.DataError) as err:
        logging.error('Setting server location failed because of wrong data')
        raise TransactionError('Setting server location failed because of wrong data')
    
    except Exception as err:
        logging.error(f'Setting server location in database failed with error - {str(err)}')
        raise TransactionError(f'Setting server location in database failed')

## Getting the status of a request
async def select_request_status(request_id):
    try:
        cur.execute('SELECT status FROM requests WHERE request_id = ?', (request_id,))    
        return cur.fetchone()
    
    except (sqlite3.OperationalError, sqlite3.DataError) as err:
        logging.error('Getting request status failed because of wrong data')
        raise TransactionError('Getting request status failed because of wrong data')
    
    except Exception as err:
        logging.error(f'Getting request status in database failed with error - {str(err)}')
        raise TransactionError(f'Getting request status in database failed')

## Getting location by domain's request id
async def select_domain_locations(request_id):
    try:
        cur.execute("SELECT DISTINCT country, region FROM servers WHERE request_id = ?", (request_id,))
        return cur.fetchall()
    
    except (sqlite3.OperationalError, sqlite3.DataError) as err:
        logging.error('Getting request locations failed because of wrong data')
        raise TransactionError('Getting request locations failed because of wrong data')
    
    except Exception as err:
        logging.error(f'Getting request locations in database failed with error - {str(err)}')
        raise TransactionError(f'Getting request locations in database failed')
        
## Getting all the domains that are connected to a country   
async def select_country_domains(country):
    try:
        cur.execute('SELECT DISTINCT requests.domain, servers.country FROM requests INNER JOIN servers ON requests.request_id = servers.request_id WHERE servers.country = ?;', (country,))
        return cur.fetchall()
    
    except (sqlite3.OperationalError, sqlite3.DataError) as err:
        logging.error('Getting request locations failed because of wrong data')
        raise TransactionError('Getting request locations failed because of wrong data')
    
    except Exception as err:
        logging.error(f'Getting domains for {country} in database failed with error - {str(err)}')
        raise TransactionError(f'Getting domains for {country} in database failed')

## Getting all the domains that are connected to a server
async def select_server_domains(server):
    try:
        cur.execute('SELECT DISTINCT requests.domain, servers.server FROM requests INNER JOIN servers ON requests.request_id = servers.request_id WHERE servers.server = ?;', (server,))
        return cur.fetchall()
    
    except (sqlite3.OperationalError, sqlite3.DataError) as err:
        logging.error('Getting request locations failed because of wrong data')
        raise TransactionError('Getting request locations failed because of wrong data')
    
    except Exception as err:
        logging.error(f'Getting domains for {server} in database failed with error - {str(err)}')
        raise TransactionError(f'Getting domains for {server} in database failed')

## Getting the most used(popular) domains
async def select_popular_domains(num):
    try:
        cur.execute('SELECT domain, COUNT(*) AS count FROM requests GROUP BY domain ORDER BY count DESC LIMIT ?;', (num,))
        return cur.fetchall()
    
    except (sqlite3.OperationalError, sqlite3.DataError) as err:
        logging.error('Getting request locations failed because of wrong data')
        raise TransactionError('Getting request locations failed because of wrong data')
    
    except Exception as err:
        logging.error(f'Getting request locations in database failed with error - {str(err)}')
        raise TransactionError(f'Getting most registered domains in database failed')

## Getting the most used(popular) servers
async def select_popular_servers(num):
    try:
        cur.execute('SELECT server, COUNT(*) AS count FROM servers GROUP BY server ORDER BY count DESC LIMIT ?;', (num,))
        return cur.fetchall()
    
    except (sqlite3.OperationalError, sqlite3.DataError) as err:
        logging.error('Getting request locations failed because of wrong data')
        raise TransactionError('Getting request locations failed because of wrong data')
    
    except Exception as err:
        logging.error(f'Getting most registered servers in database failed with error - {str(err)}')
        raise TransactionError(f'Getting most registered servers in database failed')
    
## Getting a user id of a user
async def select_user(username, password):
    try:
        cur.execute('SELECT user_id FROM users WHERE username = ? and password = ?;', (username, password))
        return cur.fetchone()
    
    except (sqlite3.OperationalError, sqlite3.DataError) as err:
        logging.error('Getting user failed because of wrong data')
        raise TransactionError('Getting user failed because of wrong data')
    
    except Exception as err:
        logging.error(f'Getting user in database failed with error - {str(err)}')
        raise TransactionError('Getting user in database failed')

## Getting all the domains with a specific status
async def select_domains_with_status(status):
    try:
        cur.execute('SELECT * FROM requests WHERE status = ?;', (status, ))
        rows = cur.fetchall()
        
        if len(rows) > 0:
            return rows
        
        return False
        
    except (sqlite3.OperationalError, sqlite3.DataError) as err:
        logging.error('Getting domains by status failed because of wrong data')
        raise TransactionError('Getting domains by status failed because of wrong data')
    
    except Exception as err:
        logging.error(f'Getting domains by status in database failed with error - {str(err)}')
        raise TransactionError('Getting domains by status in database failed')
    
## Checking if user id exists in the db
async def find_user(user_id):
    try:
        cur.execute('SELECT COUNT(*) AS users FROM users WHERE user_id = ?;', (user_id, ))
        
        if cur.fetchone()[0] > 0:
            return True
        
        return False
    
    except (sqlite3.OperationalError, sqlite3.DataError) as err:
        logging.error('Finding user failed because of wrong data')
        raise TransactionError('Finding user failed because of wrong data')
    
    except Exception as err:
        logging.error(f'Finding new user in database failed with error - {str(err)}')
        raise TransactionError('Finding new user in database failed')
    