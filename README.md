# cortex-proxy
Proxy for cortex to enable multi tenant capabilities

# How to run ?
``docker pull quay.io/debojitkakoti/cortex-proxy``

``docker run -p 8070:8070 --name cortex-proxy --network=cortex cortex-proxy:v2.0 -j abc -w http://cortex1:9009 -r http://cortex1:9009/api/prom -l 0.0.0.0:8070``

# How to contribute

Any contribution is welcome.
You can raise a pull request.

# Future scope
Need more work on http middleware and error handling
