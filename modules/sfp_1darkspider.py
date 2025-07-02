from spiderFoot import SpiderFootEvent, SpiderFootPlugin
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class sfp_darkspider(SpiderFootPlugin):
    
    def __init__(self):
        super().__init__()
        self.__name__ = "sfp_darkspider"
        self.__descr__ = "Crawls darknet websites via Tor and extract .onion links."
        self.__author__ = "name"
        self.__category__ = "Darknet"
        self.__version__ = "1.0"
        self.__opts__ = {
            "depth": 2,
            "pause": 1.0,
            "tor_proxy": "socks5h://127.0.0.1:9050"
        }
        self.__opt_help__ = {
            "depth": "Depth to crawl from the starting URL.",
            "pause": "Seconds to wait between crawl levels.",
            "tor_proxy": "SOCKS5 proxy for TOr (e.g. socks5h://127.0.0.1:9050)"
        }

    def setup (self, sfc, userOpts=dict()):
        self.sf = sfc
        for opt in userOpts:
            self.__opts__[opt] = userOpts[opt]
        
    def watchedEvents(self):
        return ["URL", "TOR_ONION_URL"]

    def producedEvents(self):
        return ["TOR_ONION_URL"]
    
    def handleEvent(self, event):
        if event.eventType != "TOR_ONION_SITE":
            return
        
        if self.checkForStop():
            return
        
        base_ur; = event.data.strip()
        self.debug(f"Starting crawl for: {base_url}")

        try:
            line_map = self.crawl(base_url)
        except Exception as e:
            self.error(f"Error during crawling {base_url}: {e}")
            return
        
        for parent, children in link_map.items():
            for child_url in children:
                if not child_url.endswith(".onion"):
                    continue
                
                if self.checkForStop():
                    return
                
                if self.state.getState(child_url):
                    continue
                
                self.state.update(child_url, True)

                evt = SpiderFootEvent("TOR_ONION_URL", child_url, self.__name__, event)
                self.notifyListeners(evt)
                
    
    def excludes(self, link: str) -> bool:
        """Filter out unwanted links such as tel:, mailto:, files, and anchors."""
        if not link:
            return True

        # Skip anchor links
        if "#" in link:
            return True

        #Skip tel/mail
        if link.startswith("tel") or link.startswith("mailto:"):
            return True
        
        # Skip media/document files
        if re.search(r"\.(pdf|jpg|jpeg|png|gif|doc|js|css)$", link, re.IGNORECASE):
            return True
        
        return False

    def cannonical(self, base:str, href: str) -> str:
        """Resolve relative URLs into absolute URLs."""
        if not href:
            return None
        if href.startswith("http"):
            return href
        return urljoin(base, href)

    def crawl_link(self, start_url):
        found_links = set()

        try:
            resp = session.get(url, timeout=15)
            if(resp.status_code != 200):
                resp.debug(f"Non-200 status at {url}: {resp.status_code}")
                return []
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exceptions as e:
            self.debug(f"Error crawling {url}: {e}")
            return []
        
        for tag in soup.find_all(["a", "area"], href=True):
            href = tag.get("href")
            if self.excludes(href):
                continue
            
            full url = self.cannonical(url, href)
            if full_url:
                found_links.add(full_url)
        
        return list(found_links)
    
    def crawl(self, root_url:str) -> Dict[str, List[str]]:
        """Crawl starting from root_url, upto configured depth, and return full crawl map."""
        all_links_map = {}
        visited = set([root_url])
        current_level = [root_url]
        prxoy = self.__opts__.get("tor_proxy", "socks5h://127.0.0.1:9050")
        depth = int(self.__opts__.get("depth", 2))

        for i in range(depth):
            session = requests.Session()
            session.proxies = {
                "http":proxy,
                "http": proxy
            }
            session.headers.update({
                "User-Agent": "Mozilla/5.0 (DarkSpider/SpiderFoot)"
            })    

            next_level = set()

            for url in current_level:
                self.debug(f"Crawling depth {i+1} -> {url}")

                link = self.crawl_link(url, session)
                all_links_map[url] = links

                for link in links:
                    if link not in visited:
                        next_level.add(link)
                        visited.add(link)  
            
            current_level = list(next_level)
    
    return all_link_map