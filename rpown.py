#!/usr/bin/python3
#
# RPOwn.py
# Tool for finding Relative Path Overwrite vulnerabilities
# If you don't know what RPO is, you can read Gareth Heyes's expanation at:
# http://www.thespanner.co.uk/2014/03/21/rpo/
#
# Writen by Ruben Piña (tr3w)
# Twitter: @tr3w_
# http://nzt-48.org
#
#


import sys
import re
import requests
import threading


from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
from selenium.common.exceptions import TimeoutException
from selenium.common.exceptions import UnexpectedAlertPresentException
from selenium.webdriver.common.keys import Keys


options = webdriver.ChromeOptions()
#options.headless = True
browser = webdriver.Chrome(options=options)


threads = 1

parameters = dict()
parameters['queryParameters'] = dict()
parameters['hasParameters'] = dict()

class RPOwn:
    
    def __init__(self, target):
        if not re.match('https?://', target): target = 'http://' + target
        if not re.match('https?://[^/]+/', target): target += '/'
        self.target = target.replace('://www.', '://')
        self.scannedLinks = set()
        self.unscannedLinks = set()
        self.externalDomains = set()
        self.s = requests.Session()
        self.allForms = []

    def get(self, url):
       
        try:
            url = url.replace(' ', '+')
            self.hostname = re.sub('(https?://)?', '', url)
            self.hostname = re.sub('/.*', '', self.hostname)
            browser.get(url)
        
        except:
            sys.stdout.write('[x] Couldn\'t establish connection with server %s\n' % (url))


    def getSource(self, url):
        
        try:
            url = url.replace(' ', '+')
            self.hostname = re.sub('(https?://)?', '', url)
            self.hostname = re.sub('/.*', '', self.hostname)
            r = self.s.get(url)
            data = r.text
            return str(data)
        except:
            sys.stdout.write('[x] Couldn\'t establish connection with server %s\n' % (url))


    def getPageSource(self, url):
        return [1, url, self.getSource(url)]
    

    def getDoctype(self, URL):
        firstTag = re.search('<.+?>', self.getSource(URL))
        firstTag = firstTag[0] if firstTag else '0'
        return 1 if re.search('<!DOCTYPE html>', firstTag, re.IGNORECASE) else 0

        
    def normalizeLink(self, link, URL):
    
        link = str(link)
        if not re.match('^(javascript:|mailto:|#)', link):
            return link
                
        else:
            return 0


    def getLinks(self, URL):
        self.get(URL)
        links = set()
        for link in browser.find_elements(By.TAG_NAME, 'a'):
            try:
                link = link.get_attribute('href')
                link = self.normalizeLink(link, URL)
                if not link:
                    continue
                urllink = link
                link = re.sub('https?://(www\.)?', '', link, 0x01)
                if re.match('^' + re.sub('(www.)?','', self.hostname), link, re.IGNORECASE):
                    links.add(re.sub('(https?)://(www\.)?', '\g<1>://', urllink, 1)
)
                else:
                    self.externalDomains.add(urllink)
            except:
                continue
        for link in links:
            if link not in self.scannedLinks:
                self.unscannedLinks.add(link)


    def getAllInputs(self, URL):
        self.get(URL)
        fields = dict()
        forms = browser.find_elements(By.XPATH, '//form')
        if forms:
            for f in range(0, len(forms)):
                #forms[f] = []
                form = browser.find_element(By.XPATH, '(//form)[%d]' % (f + 1))
                inputs = browser.find_elements(By.XPATH, '(//form)[%d]/descendant::input' % (f + 1))
                buttons = browser.find_elements(By.XPATH, '(//form)[%d]/descendant::button' % (f + 1))
                
                if inputs:
                    form_method = form.get_attribute('method')
                    form_action = form.get_attribute('action')
                    form_name = form.get_attribute('name')
                    form_onsubmit = form.get_attribute('onsubmit')
                    form_inputs = []
                    form_inputs.append({'action' : form_action})
                    current_hash = 0
                    
                    
                    for inputfield in inputs:
                        form_inputs.append({'type' : inputfield.get_attribute('type'),
                                            'name' : inputfield.get_attribute('name'),
                                            'value': inputfield.get_attribute('value')
                                            })
                        form_buttons = []
                    
                    if buttons:
                        for button in buttons:
                            form_buttons.append({'name' : button.get_attribute('name'),
                                                 'value' : button.get_attribute('value'),
                                                 'text' : button.text
                                                 })
                            
                    current_hash = hash(str(form_inputs))
                    
                    for h in self.allForms:
                        if current_hash == h:
                            return 0
                    
                    self.allForms.append(current_hash)
    
                    
                    print("\n\n[+] Found %s form in %s:" % (form_method, URL))
                    print('\t[-] <form action="%s" method="%s" name="%s">' % (form_action, form_method, form_name))
                    
                    for field in form_inputs:
                        if 'action' in field.keys():
                            continue
                        print('\t[-] <input type="%s" name="%s" value="%s" />' % (field['type'], field['name'], field['value']))                    
            
                    for button in form_buttons:
                        print('\t[-] <button name="%s" value="%s" />' % (button['name'], button['value']))
                    
                    if form_method == 'get':
                        self.attackGetForms(URL)
                        
        
    
    def attackGetForms(self, URL):
        self.get(URL)
        fields = dict()
        forms =  browser.find_elements(By.XPATH, "//form[@method='get']") 
        for i in range(0, len(forms)):
            form = browser.find_element(By.XPATH, "//form[@method='get'][%s]" % str(i + 1))
            inputs = browser.find_elements(By.XPATH, "//form[@method='get'][%s]/descendant::input" % str(i + 1))            
            if inputs:

                try:
                        
                    for c in range(0, len(inputs)):
                        if inputs[i].get_attribute('type') != 'hidden':
                            #browser.execute_script("document.getElementByName('" + inputs[i].get_attribute('name') + ").setAttribute('value', '*{bla:bla;}')")
                            inputs[i].send_keys('*{bla:bla;}')
                        
                        if c == (len(inputs) - 1):
                            inputs[i].send_keys(Keys.ENTER)
                            if re.search('\*{bla:bla;}', browser.page_source, re.IGNORECASE|re.MULTILINE):
                                print('\n\t[!] Reflected parameter found: %s' % browser.current_url)                        
                            
                except:
                    print("[x] Couldn't attack form! Please do it manually.")
                    


    def findRPO(self, URL):

        self.get(URL)
        
        styles = [ style for style in re.findall('(<link\s.*?>)', browser.page_source, re.I)
                  if "STYLESHEET" in style.upper()
                  and re.search('href=["\'](?!/|http)', style, re.I)
                 ]
        

        rpoPayload = '*{bla:bla;}'
        if len(styles):
            print('\n[!] Found RPO stylesheet at  ' + URL)
            
            for s in styles: print('\t[*] %s' %s)
            
            if not self.getDoctype(URL):
                print('\t[!] No Doctype defined!')

            injectedURL = "%s/%s/" % (URL, rpoPayload)
            browser.get(injectedURL)
            if re.search('\*{bla:bla;}', browser.page_source, re.IGNORECASE|re.MULTILINE):
                print('\t[!] Reflected URL found: %s' % injectedURL)
            
            parameters = self.parseQueryString(URL)
            if parameters:
                for key in parameters: 
                    injectedURL = re.sub(key + '=([^&]+)', '%s=\\1%s' % (key, rpoPayload),  URL)
                    browser.get(injectedURL)
                    if re.search('\*{bla:bla;}', browser.page_source, re.IGNORECASE|re.MULTILINE):
                        print('\t[!] Reflected parameter found: %s' % injectedURL)


    def parseRobots(self, URL):
        content = self.getPageSource(URL)
        if len(content):
            sys.stdout.write('[!] Found robots.txt, adding all listed directories to crawler\n')
            dirs = re.findall('(?:Dis)?allow:\\s*(.*?)', content, re.MULTILINE|re.IGNORECASE)
            for d in dirs:
                if d in self.scannedLinks():
                    continue
                self.unscannedLinks.add(d)
            sitemap = re.findall('Sitemap:\\s*(.*?)', content, re.MULTILINE|re.IGNORECASE)
            for smap in sitemap:
                sys.stdout.write('[!] Found sitemap: %s\n' % smap)



        

    def parseQueryString(self, URL):
        
        global parameters
        parameters = dict()
        if re.search('[\?#]\w+=', URL):
            queryString = re.sub('.*\?', '', URL, 1)
            parameters = dict(p.split('=') for p in queryString.split('&'))
                   


        return parameters
    

    def crawl(self):

        sys.stdout.write('\n\n')
        
        
        while 0x01:
            
            u = self.unscannedLinks.pop()
            self.scannedLinks.add(u)
            
            try:
            
                self.getLinks(u)
                self.findRPO(u)
                self.getAllInputs(u)
                
            except:
                print("\n[x] Couldn't scan %s" % u)
                
            if not len(self.unscannedLinks):
                break

        print("[+] Scanned %s pages (listed in the report)" % len(self.scannedLinks))
        print("[+] Done.")
        browser.close()
    
    def spawn_threads(self):
        self.scannedLinks.add(self.target)
        
        self.getLinks(self.target)
        for i in range(threads):
            ts = threading.Thread(target = self.crawl)
            ts.start()

if len(sys.argv) != 2: raise Exception('Usage: %s "http://target.url/"')
target = sys.argv[1]
scriptList = []
formhashes = set()
scan = RPOwn(sys.argv[1])
scan.spawn_threads()

