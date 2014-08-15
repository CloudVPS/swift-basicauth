#!/usr/bin/python
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

from setuptools import setup

setup(name='swift_basicauth',
      version='1.0.1',
      description='Basic authentication for Openstack Swift',
      author='Koert van der Veer, CloudVPS',
      author_email='koert@cloudvps.com',
      url='https://github.com/CloudVPS/swift_basicauth',
      packages=['swift_basicauth'],
      requires=['swift(>=1.7)'],
      entry_points={'paste.filter_factory':
                        ['basicauth=swift_basicauth.middleware:filter_factory']}
)