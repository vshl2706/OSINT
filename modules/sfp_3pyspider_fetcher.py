from __future__ import unicode_literals

import os
import sys
import six
import copy
import time
import json
import logging
import traceback
import functools
import threading
import tornado.ioloop
import tornado.httputil
import tornado.httpclient
import pyspider

from six.moves import queue, http_cookies
from six.moves.urllib.robotparser import RobotFileParser
from requests import cookies
from six.moves.urllib.parse import urljoin, urlsplit
from tornado import gen
from tornado.curl_httpclient import CurlAsyncHTTPClient
from tornado.simple_httpclient import SimpleAsyncHTTPClient
from tornado.httpclient import HTTPRequest

from pyspider.libs import utils, dataurl, counter
from pyspider.libs.url import quote_chinese
from .cookie_utils import extract_cookies_to_jar
logger = logging.getLogger('fetcher')

import socks
import socket

class MyCurlAsyncHTTPClient(CurlAsyncHTTPClient):
    def fetch(self, request, **kwargs):
        if isinstance(request, str):
            request = HTTPRequest(request)
        
        self.configure_proxy(request)

        logger.debug(f"Fetching {request.url} via Tor SOCKS5 proxy")

        # Perform the fetch
        return super(MyCurlAsyncHTTPClient, self).fetch(request, **kwargs)

    def configure_proxy(self, request):
        """
        Configure the request to route via Tor SOCKS5 proxy (127.0.0.1:9050)
        """
        request.proxy_host = "127.0.0.1"
        request.proxy_port = 9050
        request.proxy_type = "socks5"

def patch_socket_to_tor():
    """
    Route all HTTP requests via Tor (SOCKS5 proxy).
    Required to access .onion domains anonymously.
    """
    socket.set_default_proxy(socks.SOCKS, "127.0.0.1", 9050)
    socket.socket = socks.socksocket
    logger.info("SOCKS5 Tor proxy as been applied to socket")

patch_socket_to_tor()

tornado.httpclient.AsyncHTTPClient.configure("tornado.curl_httpclient.CurlAsyncHTTPClient")


class Fetcher(object):
    # Default User-Agent sent in HTTP requests
    user_agent = "pyspider/%s (+http://pyspider.org/)" % pyspider.__version__

    # Default options appiled to each HTTP request
    default_options = {
        'method': 'GET',    
        'headers': {},  #Additional headers
        'use_gzip': True,   #Support gzip-compressed responses\
        'timeout': 120,
        'connected_timeout': 20,    #Connection timeout
    }

    phantomjs_proxy = None
    splash_endpoint = None

    robot_txt_age = 60*60

    def __init__(self, inqueue, poolsize=100, proxy=None, async_mode=True):
        """
        Initialize the Fetcher.
        
        Args:
            inqueue: Queue from which tasks (URLs) are consumed
            outqueue: Queue where results are pushed
            poolsize: Max concurrent connections
            proxy: Optional proxy to be used for requests (e.g., Tor SOCKS5)
            async_mode: Whether to use async (non-blocking) mode
        """
        self.inqueue = inqueue      #Tasks to fetch
        self.outqueue = outqueue    #Completed fetch results
        self.poolsize = poolsize    #Concurrency limit
        self._running = False       #Internal state
        self._quit = False          #Exit flag
        self.proxy = proxy          #Proxy (if any)
        self.async_mode=async_mode
        self.ioloop = tornado.ioloop.IOLoop()   #Tornado event loop for async tasks
        self.robots_txt_cache = {}   # Cache for robots.txt per domain

        # Bind Tornado's HTTP client to this loop
        if self.async_mode:
            self.http_client = MyCurlAsyncHTTPClient(
                max_clients=self.poolsize,
                io_loop=self.ioloop
            )
        else:
            self.http_client = tornado.httpclient.HTTPClient(
                MyCurlAsyncHTTPClient, max_clients=self.poolsize
            )

    def send_results(self, type, task, result):
        """
        Send the fetch result to the output queue (SpiderFoot processor module).

        Args:
            type (str): The fetcher type used ('http', 'phantomjs', etc.).
            task (dict): The input task that was processed.
            result (dict): The result of the fetch operation.
        """
        if self.outqueue:
            try:
                self.outqueue.put((task, result))
            except Exception as e:
                logger.exception("Failed to enqueue fetch result: %s", e)

    def fetch(self, task, callback=None):
        """
        Entry point to fetch a task either asynchronously or synchronously
        depending on `self.async_mode`.

        Args:
            task (dict): The task to fetch.
            callback (func): Callback to invoke with the result.

        Returns:
            Coroutine or result of fetch.
        """

        if self.async_mode:
            return self.async_fetch(task, callback)
        else:
            return self.async_fetch(task, callback).result()
    
    @gen.Coroutine
    def async_fetch(self, task, callback=None):
        """
        Perform the actual fetch based on fetch_type in the task.

        Args:
            task (dict): The task describing the URL and fetch type.
            callback (func): Callback function to handle result.

        Returns:
            Tornado Future that yields the fetch result.
        """
        url = task.get('url','data:,')
        if callback is None:
            callback = self.send_result
        
        type = 'None'
        start_time = time.time()

        try:
            if url.startswith('data:'):
                type = 'data'
                result = yield gen.maybe_future(self.data_fetch(url, task))
            elif task.get('fetch', {}).get('fetch_type') in ('js', 'phantomjs'):
                type = 'phantomjs'
                result = yield self.phantomjs_fetch(url, task)
            elif task.get('fetch', {}).get('fetch_type') in ('js', phantomjs):
                type = 'phantomjs'
                result = yield self.phantomjs_fetch(url, task)
            elif task.get('fetch', {}).get('fetch_type')in ('splash'):
                type = 'splash'
                result = yield self.splash_fetch(url, task)
            elif task.get('fetch', {}).get('fetch_type') in ('puppeter', ):
                type = 'pupperteer'
                result = yield self.puppeteer_fetch(url, task)
            else:
                type = 'http'
                result = yield self.http_fetch(url, task)
        except Exception as e:
            logger.exception("Exception occurred during fetch: %s", e)
            result = self.handle_error(type, url, task, start_time, e)

        callback(type, task, result)
        self.on_result(type, task, result)
        raise gen.Return(result)
    
    @gen.Coroutine
    def http_fetch(self, url, task):
        """
        HTTP fetcher for .onion and clearnet URLs via Tor (if proxy configured).

        Args:
            url (str): The URL to fetch.
            task (dict): Task dictionary with headers, timeouts, etc.

        Returns:
            dict: Result dictionary with content, headers, status, etc.
        """
        start_time = time.time()
        self.on_fetch('http', task)

        # Function to call when there's an error
        handle_error = lambda e: self.handle_error('http', url, task, start_time, e)
        
        fetch = self.pack_tornado_request_parameters(url, task)
        task_fetch = task.get('fetch', {})

        # Prepare a session for cookies
        session = cookies.RequestCookieJar()

        # Convert 'Cookie' geader string to cookie jar
        if 'Cookie' in fetch['headers']:
            c = http_cookies.SimpleCookie()
            try:
                c.load(fetch['headers']['Cookie'])
            except AttributeError:
                c.load(utils.utf8(fetch['headers']['Cookie']))
            for key in c:
                session.set(key, c[key])
            del fetch['headers']['Cookie']
        
        # Add cookies from task, if any
        if 'cookies' in fetch:
            session.update(fetch['cookies'])
            del fetch['cookies']

        #Set redirect limit
        max_redirects = task_fetch.get('max_redirects', 5)
        fetch['follow_redirects'] = False # We are handling redirects manually to retain cookies
