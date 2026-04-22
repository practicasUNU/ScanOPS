class ZAPv2:
    def __init__(self, proxies=None):
        self.spider = self.Spider()
        self.ascan = self.Ascan()
        self.alert = self.Alert()
    class Spider:
        def scan(self, url): pass
        def status(self): return 100
    class Ascan:
        def scan(self, url): pass
        def status(self): return 100
    class Alert:
        def alerts(self, baseurl=None):
            return [{'name': 'SQL Injection', 'risk': 'High', 'alertRef': '40018', 'url': baseurl, 'solution': 'Use parameterized queries', 'sourceId': 'http:443'}]
