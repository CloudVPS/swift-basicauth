Basic authentication for Openstack Swift
========================================

Add the WSGI filter to `/etc/swift/proxy.conf`.

	[filter:basicauth]
	use = egg:swift_basicauth#swift_basicauth
	#secret=ABCDEFG
	#auth_host=localhost
	#auth_port=5000
	#auth_protocol=http
	#cache_ttl=300.0


Then add the filter to the proxy's main pipeline, like so:

	[pipeline:main]
	pipeline = catch_errors cache authtoken basicauth keystone proxy-server

It is crucial that basicauth is placed _after_ `authtoken`, but _before_
`keystone`.