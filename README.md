Basic authentication for Openstack Swift
========================================

Add the WSGI filter to `/etc/swift/proxy.conf`.

	[filter:basicauth]
	use = egg:swift_basicauth#swift_basicauth
	#auth_host=localhost
	#auth_port=5000
	#auth_protocol=http
	#token_cache_time=300.0


Then add the filter to the proxy's main pipeline, just before authtoken like so:

	[pipeline:main]
	pipeline = catch_errors cache basicauth authtoken keystone proxy-server
