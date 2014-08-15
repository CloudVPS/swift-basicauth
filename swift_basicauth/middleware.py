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
import iso8601
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

        self.token_cache_time = float(conf['token_cache_time'])
        self.storage_url_template = conf['storage_url_template'].replace("^","%")
        self.realm = conf['realm']

        # where to find the auth service (we use this to validate tokens)
        self.auth_host = conf['auth_host']
        self.auth_port = int(conf['auth_port'])
        auth_protocol = conf['auth_protocol']

        if auth_protocol == 'http':
            self.http_client_class = httplib.HTTPConnection
        else:
            self.http_client_class = httplib.HTTPSConnection

        self._cache = None

    def get_authorization(self, env):
        if 'HTTP_AUTHORIZATION' in env:
            auth_type, authorization = env['HTTP_AUTHORIZATION'].split(None, 1)
            if auth_type.lower() == 'basic':
                authorization = base64.b64decode(authorization)
                user_name, password = authorization.rsplit(':', 1)

                return user_name, password, False

        user_name = (env.get('HTTP_X_STORAGE_USER') or
                     env.get('HTTP_X_AUTH_USER'))
        password = (env.get('HTTP_X_STORAGE_PASS') or
                    env.get('HTTP_X_AUTH_KEY'))

        return user_name, password, bool(user_name or password)

    def authorize(self, user_name, tenant_id, password):

        if self._cache:
            key = "basicauth:%s:%s:%s" % (user_name, tenant_id, password)
            token = self._cache.get(key)

            if token:
                return token

        conn = self.http_client_class(self.auth_host, self.auth_port)

        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
        }

        body = {
            "auth": {
                "passwordCredentials": {
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

        if response.status == 200 and token_info:
            token = token_info['access']['token']['id']

            if self._cache:
                self._cache.set(key, token, timeout=self.token_cache_time)

                # store the token in memcache
                timestamp = token_info['access']['token']['expires']
                expires = iso8601.parse_date(timestamp).strftime('%s')

                self._cache.set('tokens/%s' % token,
                                (token_info, expires),
                                timeout=self.token_cache_time)

            return token

    def __call__(self, env, start_response):

        user_name, password, keystone_v1 = self.get_authorization(env)

        # try to determine the account
        if user_name and password:

            if self._cache is None:
                self._cache = cache_from_env(env)

            if ':' in user_name:
                tenant_id, user_name = user_name.split(':', 1)
            else:
                _, tenant_id, _ = split_path(env['RAW_PATH_INFO'], 1, 3, True)

            # Remove reseller prefix
            tenant_id = tenant_id.split('_', 1)[-1]

            token = self.authorize(user_name, tenant_id, password)

            if not token:
                headers = [('WWW-Authenticate', 'Basic realm="Object store"')]
                start_response('401 Not Authorized', headers)
                self.logger.info('Authentication failed for %s:%s',
                                 tenant_id, user_name)
                return "Invalid credentials"
            elif keystone_v1:
                # favor original_ version of host and path, as those are
                # provided for exactly this purpose: url reconstruction.
                url = self.storage_url_template % {
                    'host': (env.get('HTTP_ORIGINAL_HOST') or
                             env.get('HTTP_HOST', 'localhost')),
                    'path': (env.get('HTTP_ORIGINAL_PATH') or
                             env.get('RAW_PATH_INFO')),
                    'tenant_id': tenant_id,
                }

                start_response("204 No content", [
                    ('X-Storage-Url', url),
                    ('X-Server-Management-Url', "None"),  # for libcloud
                    ('X-CDN-Management-Url', "None"),  # for libcloud
                    ('X-Auth-Token', token),
                ])

                return ""

            env['HTTP_X_AUTH_TOKEN'] = token

        # Append the WWW-authenticate headers for 401 responses, so
        # browser-based clients can try to authenticate
        def wrap_start_response(status, headers, exc_info=None):
            if status.startswith("401 "):
                headers = (headers.items() if isinstance(headers, dict)
                           else headers)
                headers.append(("WWW-Authenticate",
                                'Basic realm="%s"' % self.realm))

            if exc_info:
                return start_response(status, headers, exc_info)
            else:
                return start_response(status, headers)

        nonbasic_tried = (
            ('HTTP_X_AUTH_TOKEN' in env)
            or keystone_v1
            or 'temp_url_sig=' in env.get('QUERY_STRING', ''))

        if nonbasic_tried:
            # Don't send www-authenticate when a different auth method was
            # tried
            return self.app(env, start_response)
        else:
            return self.app(env, wrap_start_response)


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""

    # default configuration
    conf = {
        'auth_host': 'localhost',
        'auth_port': 5000,
        'auth_protocol': 'http',
        'token_cache_time': 300.0,
        'storage_url_template': 'http://^(host)s/v1/AUTH_^(tenant_id)s',
        'realm': 'Openstack Swift',
    }

    conf.update(global_conf)
    conf.update(local_conf)

    def basicauth_filter(app):
        return BasicAuthMiddleware(app, conf)

    return basicauth_filter
