from spiderfoot import SpiderFootPlugin, SpiderFootEvent
from modules.pyspider_fetcher import Fetcher
import queue
import logging

class sfp_pyspider_bridge(SpiderFootPlugin):

    def __init__(self):
        super().__init__()
        self.queue_in = queue.Queue()
        self.queue_out = queue.Queue()
        self.fetcher = None

    def setup(self, sfc, userOpts=dict()):
        self.fetcher = Fetcher(self.queue_in, self.queue_out, proxy="socks5h://127.0.0.1:9050")
        # Optionally start fetcher in thread or async loop here

    def watchedEvents(self):
        return ["TOR_DOMAIN_NAME", "URL"]

    def producedEvents(self):
        return ["TOR_ONION_URL"]

    def handleEvent(self, event):
        target = event.data
        if not target.startswith("http"):
            return

        self.info(f"[PyspiderBridge] Crawling: {target}")
        self.queue_in.put({
            "url": target,
            "callback": "parse",  # Optional: name of callback if you're emulating Pyspider job
        })

        try:
            result = self.queue_out.get(timeout=60)  # Adjust timeout as needed
            if result and 'url' in result:
                evt = SpiderFootEvent("TOR_ONION_URL", result['url'], self.__name__, event)
                self.notifyListeners(evt)
        except queue.Empty:
            self.info("No response from fetcher.")
