

import re
import time
import socket
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import requests
from requests.exceptions import RequestException
from spiderfoot import SpiderFootEvent
from spiderfoot import SpiderFootPlugin

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class sfp_4onionLeakHunter(SpiderFootPlugin):
    meta = {
        'name': "Tor Keyword Hunter",
        'summary': "Finds leaked data on darknet sites using keywords",
        'flags': ["tor", "slow", "risky"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "http://example.com",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [],
            'favIcon': "",
            'logo': "",
            'description': "Searches Tor hidden services for leaked data matching keywords."
        }
    }


opts = {
    # 'keyword': 'DRDO, defence, classified',
    'keyword': 'Insider Wallet, Superlist',
    'tor_proxy': 'socks5h://127.0.0.1:9150',
    'max_depth': 2,
    'max_pages': 5,
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0',
    'timeout': 90,
    'verify': False,
    'forum_patterns': [
        r'/forum/',
        r'/board/',
        r'/thread',
        r'/topic',
        r'/index\.php\?topic=',
        r'\.php\?board='
    ]
}


    optdescs = {
        'keyword': "Comma-separated keywords (e.g., DRDO,defence,classified)",
        'tor_proxy': "Tor SOCKS5 proxy (socks5h://host:port)",
        'max_depth': "Maximum recursion depth",
        'max_pages': "Maximum pages to retrieve",
        'user_agent': "HTTP User-Agent header",
        'timeout': "Request timeout in seconds",
        'verify': "Verify SSL certificates"
    }

    results = None
    visited_urls = set()
    page_count = 0
    keyword_list = list()
    tor_available = True

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.visited_urls = set()
        self.page_count = 0
        self.tor_available = True
        
        # Override options with user-supplied values
        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]
        
        # Parse keywords
        if self.opts['keyword']:
            self.keyword_list = [k.strip().lower() for k in self.opts['keyword'].split(',')]
            self.sf.info(f"Keywords set: {', '.join(self.keyword_list)}")
        else:
            self.sf.error("No keywords specified - module will only crawl")
            self.keyword_list = []

        # Validate Tor proxy format
        if not re.match(r'^socks5h?://[a-zA-Z0-9\.\-]+:\d+$', self.opts['tor_proxy']):
            self.sf.error("Invalid Tor proxy format - use socks5h://host:port")
            self.tor_available = False
            return True

        # Test Tor connectivity
        try:
            parsed = urlparse(self.opts['tor_proxy'])
            proxy_host = parsed.hostname
            proxy_port = parsed.port if parsed.port else 9050
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((proxy_host, proxy_port))
            sock.close()
            self.sf.info("Tor proxy connection successful")
        except Exception as e:
            self.sf.error(f"Tor proxy connection failed: {str(e)}")
            self.sf.error("Ensure Tor is running and accessible at " + self.opts['tor_proxy'])
            self.tor_available = False

        return True

    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    def producedEvents(self):
        return ["LEAKED_DATA", "DARKNET_MENTION_CONTENT", "RAW_DATA"]

    def handleEvent(self, event):
        eventData = event.data

        if not self.tor_available:
            self.sf.error("Skipping event - Tor proxy unavailable")
            return
            
        if not eventData.endswith(".onion"):
            self.sf.debug(f"Skipping {eventData}, not an onion domain")
            return

        self.sf.info(f"Starting Tor crawl on: {eventData}")
        base_url = f"http://{eventData}"
        self.crawl_site(base_url, depth=0)

    def create_session(self):
        """Create requests session with Tor proxy"""
        session = requests.Session()
        session.proxies = {'http': self.opts['tor_proxy'], 'https': self.opts['tor_proxy']}
        session.headers = {'User-Agent': self.opts['user_agent']}
        session.verify = self.opts['verify']
        return session

    def fetch_page(self, session, url):
        """Fetch URL through Tor with error handling"""
        try:
            self.sf.debug(f"Fetching: {url}")
            response = session.get(
                url,
                timeout=self.opts['timeout'],
                allow_redirects=True
            )
            response.raise_for_status()
            return response
        except RequestException as e:
            self.sf.error(f"Request failed: {str(e)}")
        except Exception as e:
            self.sf.error(f"Unexpected error: {str(e)}")
        return None

    def is_forum_page(self, url, content):
        """Check if page is a forum"""
        # Check URL patterns
        for pattern in self.opts['forum_patterns']:
            if re.search(pattern, url, re.IGNORECASE):
                return True
                
        # Check content for forum indicators
        forum_indicators = [
            "forum", "board", "thread", "topic", 
            "posts:", "members:", "last post", 
            "reply", "new topic", "page 1 of"
        ]
        
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in forum_indicators)

    def contains_keywords(self, content):
        """Check if content contains target keywords"""
        if not self.keyword_list:
            return None
            
        content_lower = content.lower()
        found_keywords = list()
        
        for keyword in self.keyword_list:
            if keyword in content_lower:
                found_keywords.append(keyword)
        
        return found_keywords if found_keywords else None

    def extract_snippet(self, content, keywords, context_chars=200):
        """Extract relevant text around found keywords, prefer full paragraph."""
        soup = BeautifulSoup(content, 'html.parser')
        snippets = []
        content_lower = content.lower()
        for keyword in keywords:
            # Find all occurrences of the keyword in the text
            for match in soup.find_all(string=re.compile(re.escape(keyword), re.IGNORECASE)):
                parent = match.find_parent(['p', 'div', 'li', 'span'])
                if parent:
                    snippet = parent.get_text(separator=' ', strip=True)
                    if snippet and snippet not in snippets:
                        snippets.append(snippet)
                else:
                    # Fallback: extract context_chars around the keyword
                    pos = content_lower.find(keyword)
                    if pos != -1:
                        start = max(0, pos - context_chars)
                        end = min(len(content), pos + len(keyword) + context_chars)
                        snippet = content[start:end].replace('\n', ' ').replace('\r', '')
                        snippets.append(snippet)
        return "\n\n".join(snippets) if snippets else "No snippet available"

    def extract_links(self, base_url, content):
        """Extract unique same-domain links from page content"""
        soup = BeautifulSoup(content, 'html.parser')
        links = set()
        
        for link in soup.find_all('a', href=True):
            href = link['href'].strip()
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            
            # Only process same-domain .onion links
            if parsed.netloc.endswith('.onion') and parsed.scheme.startswith('http'):
                links.add(full_url)
        
        return links

    def crawl_site(self, start_url, depth):
        """Recursive crawling with depth control"""
        if (self.page_count >= self.opts['max_pages'] or 
            depth > self.opts['max_depth'] or 
            self.checkForStop()):
            return

        if start_url in self.visited_urls:
            return
            
        self.visited_urls.add(start_url)
        session = self.create_session()
        response = self.fetch_page(session, start_url)
        
        if not response:
            return
            
        self.page_count += 1
        content = response.text
        self.sf.info(f"Fetched page {self.page_count}/{self.opts['max_pages']}: {start_url}")
        
        # Save to debug file
        with open(f"page_{self.page_count}.html", "w", encoding="utf-8") as f:
            f.write(content)
        
        # Check if this is a forum page
        is_forum = self.is_forum_page(start_url, content)
        
        # Keyword detection
        found_keywords = self.contains_keywords(content)
        if found_keywords:
            snippet = self.extract_snippet(content, found_keywords)
            self.sf.info(f"Found keywords {', '.join(found_keywords)} in {start_url}")
            
            # Create detailed leak event
            leak_data = f"KEYWORDS: {', '.join(found_keywords)}\nURL: {start_url}\nSNIPPET:\n{snippet}"
            
            leak_event = SpiderFootEvent(
                "LEAKED_DATA",
                leak_data,
                self.__name__,
                start_url
            )
            self.notifyListeners(leak_event)
            
            # Create specialized event for forums, now with snippet
            if is_forum:
                forum_event = SpiderFootEvent(
                    "DARKNET_MENTION_CONTENT",
                    f"FORUM LEAK: {', '.join(found_keywords)}\nURL: {start_url}\nSNIPPET:\n{snippet}",
                    self.__name__,
                    start_url
                )
                self.notifyListeners(forum_event)
            if not found_keywords:
                self.sf.debug(f"No keywords found in {start_url}")
        
        # Recursive crawling
        if depth < self.opts['max_depth']:
            new_links = self.extract_links(start_url, content)
            for link in new_links:
                if self.page_count >= self.opts['max_pages'] or self.checkForStop():
                    break
                if link not in self.visited_urls:
                    # Prioritize forum links
                    if any(p in link for p in ['/forum/', '/board/', '/thread', '/topic']):
                        self.crawl_site(link, depth + 1)
                    else:
                        time.sleep(3)  # Throttle non-forum requests
                        self.crawl_site(link, depth + 1)

# For direct testing
if __name__ == '__main__':
    print("Testing Tor Leak Hunter Module")
    from spiderfoot import SpiderFoot
    sf = SpiderFoot()
    
    # Initialize module
    mod = sfp_4onionLeakHunter()
    mod.setup(sf, {
        'keyword': 'DRDO,defence,classified',
        'tor_proxy': 'socks5h://127.0.0.1:9050',
        'timeout': '30',
        'max_depth': '1',
        'max_pages': '3'
    })
    
    # Create test event
    test_event = SpiderFootEvent("DOMAIN_NAME", "dreadditevelidot.onion", "", None)
    mod.handleEvent(test_event)
    print("Test completed. Check SpiderFoot events.")





# import re
# import time
# import socket
# import urllib3
# from collections import deque
# from bs4 import BeautifulSoup
# from urllib.parse import urlparse, urljoin
# import requests
# from requests.exceptions import RequestException
# from spiderfoot import SpiderFootEvent
# from spiderfoot import SpiderFootPlugin

# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# class sfp_4onionLeakHunter(SpiderFootPlugin):
#     meta = {
#         'name': "Tor Keyword Hunter",
#         'summary': "Finds leaked data on darknet sites using keywords",
#         'flags': ["tor", "slow", "risky"],
#         'useCases': ["Footprint", "Investigate"],
#         'categories': ["Leaks, Dumps and Breaches"],
#         'dataSource': {
#             'website': "http://example.com",
#             'model': "FREE_NOAUTH_UNLIMITED",
#             'references': [],
#             'favIcon': "",
#             'logo': "",
#             'description': "Searches Tor hidden services for leaked data matching keywords."
#         }
#     }

#     opts = {
#         'keyword': 'Insider Wallet, Superlist',
#         'tor_proxy': 'socks5h://127.0.0.1:9150',
#         'max_depth': 2,
#         'max_pages': 5,
#         'user_agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0',
#         'timeout': 90,
#         'verify': False,
#         'forum_patterns': [
#             r'/forum/',
#             r'/board/',
#             r'/thread',
#             r'/topic',
#             r'/index\.php\?topic=',
#             r'\.php\?board='
#         ]
#     }

#     optdescs = {
#         'keyword': "Comma-separated keywords (e.g., DRDO,defence,classified)",
#         'tor_proxy': "Tor SOCKS5 proxy (socks5h://host:port)",
#         'max_depth': "Maximum recursion depth",
#         'max_pages': "Maximum pages to retrieve",
#         'user_agent': "HTTP User-Agent header",
#         'timeout': "Request timeout in seconds",
#         'verify': "Verify SSL certificates"
#     }

#     results = None
#     visited_urls = set()
#     page_count = 0
#     keyword_list = list()
#     tor_available = True
#     forum_regexes = []

# def setup(self, sfc, userOpts=dict()):
#     self.sf = sfc
#     self.results = self.tempStorage()
#     self.visited_urls = set()
#     self.page_count = 0
#     self.tor_available = True
    
#     # Override options with user-supplied values
#     for opt in list(userOpts.keys()):
#         self.opts[opt] = userOpts[opt]
    
#     # Convert numeric options to integers with validation
#     numeric_options = {
#         'max_depth': 10,
#         'max_pages': 5,
#         'timeout': 90
#     }
    
#     for opt, default in numeric_options.items():
#         try:
#             self.opts[opt] = int(self.opts.get(opt, default))
#         except (ValueError, TypeError):
#             self.sf.error(f"Invalid value for {opt} ({self.opts[opt]}). Using default {default}.")
#             self.opts[opt] = default
    
#     # Pre-compile forum regex patterns
#     self.forum_regexes = [re.compile(pattern, re.IGNORECASE) 
#                          for pattern in self.opts['forum_patterns']]
    
#     if self.opts['keyword']:
#         self.keyword_list = [k.strip().lower() for k in self.opts['keyword'].split(',')]
#         self.sf.info(f"Keywords set: {', '.join(self.keyword_list)}")
#     else:
#         self.sf.error("No keywords specified - module will only crawl")
#         self.keyword_list = []

#     if not re.match(r'^socks5h?://[a-zA-Z0-9\.\-]+:\d+$', self.opts['tor_proxy']):
#         self.sf.error("Invalid Tor proxy format - use socks5h://host:port")
#         self.tor_available = False
#         return True

#     try:
#         parsed = urlparse(self.opts['tor_proxy'])
#         proxy_host = parsed.hostname
#         proxy_port = parsed.port if parsed.port else (9050 if "9050" in self.opts['tor_proxy'] else 9150)
        
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         sock.settimeout(5)
#         sock.connect((proxy_host, proxy_port))
#         sock.close()
#         self.sf.info("Tor proxy connection successful")
#     except Exception as e:
#         self.sf.error(f"Tor proxy connection failed: {str(e)}")
#         self.sf.error("Ensure Tor is running and accessible at " + self.opts['tor_proxy'])
#         self.tor_available = False

#     return True

#     def watchedEvents(self):
#         return ["DOMAIN_NAME"]

#     def producedEvents(self):
#         return ["LEAKED_DATA", "DARKNET_MENTION_CONTENT", "RAW_DATA"]

#     def handleEvent(self, event):
#         eventData = event.data

#         if not self.tor_available:
#             return
            
#         if not eventData.endswith(".onion"):
#             self.sf.debug(f"Skipping {eventData}, not an onion domain")
#             return

#         self.sf.info(f"Starting Tor crawl on: {eventData}")
#         base_url = f"http://{eventData}"
#         target_domain = eventData  # Store target domain for same-domain check
        
#         session = self.create_session()
#         queue = deque()
#         seen_urls = set()
        
#         seen_urls.add(base_url)
#         queue.append((base_url, 0))
        
#         while queue and self.page_count < self.opts['max_pages'] and not self.checkForStop():
#             url, depth = queue.popleft()
            
#             if url in self.visited_urls:
#                 continue
                
#             # Throttle non-forum requests
#             if depth > 0:
#                 if not any(r.search(url) for r in self.forum_regexes):
#                     time.sleep(3)
            
#             self.visited_urls.add(url)
#             response = self.fetch_page(session, url)
            
#             if not response:
#                 continue
                
#             self.page_count += 1
#             content = response.text
#             self.sf.info(f"Fetched page {self.page_count}/{self.opts['max_pages']}: {url}")
            
#             # Emit RAW_DATA event
#             raw_event = SpiderFootEvent(
#                 "RAW_DATA",
#                 content,
#                 self.__name__,
#                 url
#             )
#             self.notifyListeners(raw_event)
            
#             # Check content type
#             is_forum = self.is_forum_page(url, content)
            
#             # Keyword detection
#             found_keywords = self.contains_keywords(content)
#             if found_keywords:
#                 snippet = self.extract_snippet(content, found_keywords)
#                 self.sf.info(f"Found keywords {', '.join(found_keywords)} in {url}")
                
#                 leak_data = f"KEYWORDS: {', '.join(found_keywords)}\nURL: {url}\nSNIPPET:\n{snippet}"
#                 leak_event = SpiderFootEvent(
#                     "LEAKED_DATA",
#                     leak_data,
#                     self.__name__,
#                     url
#                 )
#                 self.notifyListeners(leak_event)
                
#                 if is_forum:
#                     forum_event = SpiderFootEvent(
#                         "DARKNET_MENTION_CONTENT",
#                         f"FORUM LEAK: {', '.join(found_keywords)}\nURL: {url}\nSNIPPET:\n{snippet}",
#                         self.__name__,
#                         url
#                     )
#                     self.notifyListeners(forum_event)
#             else:
#                 self.sf.debug(f"No keywords found in {url}")
            
#             # Process links
#             if depth < self.opts['max_depth']:
#                 links = self.extract_links(url, content, target_domain)
#                 forum_links = []
#                 non_forum_links = []
                
#                 for link in links:
#                     if link in seen_urls:
#                         continue
#                     seen_urls.add(link)
                    
#                     if any(r.search(link) for r in self.forum_regexes):
#                         forum_links.append(link)
#                     else:
#                         non_forum_links.append(link)
                
#                 # Prioritize forum links
#                 for link in forum_links:
#                     queue.appendleft((link, depth + 1))
#                 for link in non_forum_links:
#                     queue.append((link, depth + 1))

#     def create_session(self):
#         session = requests.Session()
#         session.proxies = {'http': self.opts['tor_proxy'], 
#                           'https': self.opts['tor_proxy']}
#         session.headers = {'User-Agent': self.opts['user_agent']}
#         session.verify = self.opts['verify']
#         return session

#     def fetch_page(self, session, url):
#         try:
#             self.sf.debug(f"Fetching: {url}")
#             response = session.get(
#                 url,
#                 timeout=self.opts['timeout'],
#                 allow_redirects=True
#             )
#             response.raise_for_status()
#             return response
#         except RequestException as e:
#             self.sf.error(f"Request failed: {str(e)}")
#         except Exception as e:
#             self.sf.error(f"Unexpected error: {str(e)}")
#         return None

#     def is_forum_page(self, url, content):
#         for regex in self.forum_regexes:
#             if regex.search(url):
#                 return True
                
#         content_lower = content.lower()
#         indicators = [
#             "forum", "board", "thread", "topic", 
#             "posts:", "members:", "last post", 
#             "reply", "new topic", "page 1 of"
#         ]
#         return any(ind in content_lower for ind in indicators)

#     def contains_keywords(self, content):
#         if not self.keyword_list:
#             return None
            
#         content_lower = content.lower()
#         found_keywords = []
        
#         for keyword in self.keyword_list:
#             if keyword in content_lower:
#                 found_keywords.append(keyword)
        
#         return found_keywords or None

#     def extract_snippet(self, content, keywords):
#         soup = BeautifulSoup(content, 'html.parser')
#         snippets = []
        
#         for keyword in keywords:
#             for element in soup.find_all(string=re.compile(re.escape(keyword), 
#                                        recursive=True)):
#                 parent = element.find_parent(['p', 'div', 'li', 'article', 'section'])
#                 if parent:
#                     text = parent.get_text(separator=' ', strip=True)
#                     if text and text not in snippets:
#                         snippets.append(text)
#         return "\n\n".join(snippets[:3]) if snippets else "No relevant snippet found"

#     def extract_links(self, base_url, content, target_domain):
#         soup = BeautifulSoup(content, 'html.parser')
#         links = set()
        
#         for link in soup.find_all('a', href=True):
#             href = link['href'].strip()
#             full_url = urljoin(base_url, href)
#             parsed = urlparse(full_url)
#             domain = parsed.netloc.split(':')[0]  # Remove port
            
#             if (domain == target_domain and 
#                 parsed.scheme in ['http', 'https']):
#                 links.add(full_url)
        
#         return links

# # Test code remains unchanged
# if __name__ == '__main__':
#     print("Testing Tor Leak Hunter Module")
    
#     # Create minimal mock classes
#     class SpiderFoot:
#         def info(self, msg): print(f"[INFO] {msg}")
#         def error(self, msg): print(f"[ERROR] {msg}")
#         def debug(self, msg): print(f"[DEBUG] {msg}")
#         def tempStorage(self): return dict()
        
#     class SpiderFootEvent:
#         def __init__(self, eventType, data, source, parent):
#             self.eventType = eventType
#             self.data = data
#             self.source = source
#             self.parent = parent
            
#     sf = SpiderFoot()
    
#     # Initialize module
#     mod = sfp_4onionLeakHunter()
#     mod.setup(sf, {
#         'keyword': 'DRDO,defence,classified',
#         'tor_proxy': 'socks5h://127.0.0.1:9050',
#         'timeout': '120',
#         'max_depth': '15',
#         'max_pages': '3'
#     })
    
#     test_event = SpiderFootEvent("DOMAIN_NAME", "dreadyj7l26jqvyk3xycgljkkagc32x2y5urlcse3qocylzn53oj2byd.onion", "", None)
#     mod.handleEvent(test_event)
#     print("Test completed. Check console output.")