# Copyright 2013 CloudVPS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import httplib
import json

from swift.common.utils import get_logger, split_path, cache_from_env

class KeystoneError(Exception):
    pass

class BasicAuthMiddleware(object):
    """HTTP Basic authentication middleware"""
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(self.conf, log_route='basicauth')

        self.hash_secret = conf['secret']

        # where to find the auth service (we use this to validate tokens)
        self.auth_host = conf['auth_host']
        self.auth_port = int(conf['auth_port'])
        auth_protocol = conf['auth_protocol']

        self.cache_ttl = float(conf['cache_ttl'])

        if auth_protocol == 'http':
            self.http_client_class = httplib.HTTPConnection
        else:
            self.http_client_class = httplib.HTTPSConnection

        self.memcache = None

    def get_authorization(self, env):
        if 'HTTP_AUTHORIZATION' in env:
            auth_type, authorization = env['HTTP_AUTHORIZATION'].split(None, 1)
            if auth_type.lower() == 'basic':
                authorization = base64.b64decode(authorization)
                return authorization.rsplit(':', 1)

        user_name = env.get('HTTP_X-STORAGE-USER') or \
                   env.get('HTTP_X-AUTH-USER')
        password = env.get('HTTP_X-STORAGE-PASS') or \
                   env.get('HTTP_X-AUTH-KEY')

        return user_name, password

    def authorize(self, user_name, tenant_id, password):
        if self.memcache:
            key = "%s:%s:%s:%s" %( self.secret, user_name, tenant_id, password)
            token_info = self.memcache.get(key)

            if token_info:
                return token_info

        conn = self.http_client_class(self.auth_host, self.auth_port)

        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
        }

        body = {
            "auth":{
                "passwordCredentials":{
                    "username": user_name,
                    "password": password
                },
                "tenantId": tenant_id
            }
        }

        body = json.dumps(body)

        try:
            conn.request("POST", "/v2.0/tokens", headers=headers, body=body)
            response = conn.getresponse()
            body = response.read()
        except Exception, e:
            self.logger.error('HTTP connection exception: %s' % e)
            raise KeystoneError('Unable to communicate with keystone')
        finally:
            conn.close()

        try:
            token_info = json.loads(body)
        except ValueError:
            self.logger.warn('Keystone did not return json-encoded body')
            token_info = {}

        if token_info and self.memcache:
            self.memcache.set(key, token_info, ttl=self.cache_ttl)

        return token_info

    def __call__(self, env, start_response):

        user_name, password = self.get_authorization(env)

        # try to determine the account
        if user_name and password:
            if ':' in user_name:
                tenant_id, user_name = user_name.split(':', 1)
            else:
                _, tenant_id, _ = split_path(env['RAW_PATH_INFO'], 1, 3, True)

            if self.memcache is None:
                self.memcache = cache_from_env(env)

            token_info = self.authorize(user_name, tenant_id, password)

            user = token_info['access']['user']
            #token = token_info['access']['token']
            roles = ','.join([role['name'] for role in user.get('roles', [])])

            user_id = user['id']
            user_name = user['name']
            tenant_name = token_info['tenant']['name']

            env.update({
                'X-Identity-Status': 'Confirmed',
                'X-Tenant-Id': tenant_id,
                'X-Tenant-Name': tenant_name,
                'X-User-Id': user_id,
                'X-User-Name': user_name,
                'X-Roles': roles,
                # Deprecated
                'X-User': user_name,
                'X-Tenant': tenant_name,
                'X-Role': roles,
            })

            # TODO: add x-storage-url and x-storage-token to response if we're
            # mimicking keystone v1 auth

        return self.app(env, start_response)

def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""

    # default configuration
    conf = {
        'secret': '',
        'auth_host': 'localhost',
        'auth_port': 5000,
        'auth_protocol': 'http',
        'cache_ttl': 300.0,
    }

    conf.update(global_conf)
    conf.update(local_conf)

    def basicauth_filter(app):
        return BasicAuthMiddleware(app, conf)

    return basicauth_filter
