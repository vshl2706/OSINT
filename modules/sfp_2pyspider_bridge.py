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

from pyspider.libs import utils, dataurl, counter
from pyspider.libs.url import quote_chinese
from .cookie_utils import extract_cookies_to_jar
logger = logging.getLogger('fetcher')

import socks
import socket

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