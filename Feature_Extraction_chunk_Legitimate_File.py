import pandas as pd
import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime
from urllib.parse import urlparse,urlencode
import ipaddress
import re
import requests
import urllib3
import jsbeautifier

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#loading the Legit URLs data to dataframe
data0 = pd.read_csv("Legit_urls.csv")
data0.tail
data0.columns

#URLs.shape
#print(data0['URL'].apply(type).unique())

# The extracted features are categorized into
# 1.   Address Bar based Features
# 2.   HTML & Javascript based Features

#Address Bar Based Features:**
# *   Domain of URL
# *   IP Address in URL
# *   "@" Symbol in URL
# *   Length of URL
# *   Depth of URL
# *   Redirection "//" in URL
# *   "http/https" in Domain name
# *   Using URL Shortening Services “TinyURL”
# *   Prefix or Suffix "-" in Domain

# ## 1.1. Domain of the URL (Domain)
# Here, we are just extracting the domain present in the URL. This feature doesn't have much significance in the training. May even be dropped while training the model.

#def getDomain(url):
#    domain = urlparse.urlparse(url).netloc
#    if re.match(r"^www\.", domain):
#        domain = domain.replace("www.", "")
#    return domain

# #### **1.2.Checks for IP address in URL (Have_IP)
# Checks for the presence of IP address in the URL. URLs may have IP address instead of domain name. If an IP address is used as an alternative of the domain name in the URL, we can be sure that someone is trying to steal personal information with this URL.

# If the domain part of URL has IP address, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).

def havingIP(url):
  try:
    ipaddress.ip_address(url)
    ip = 1
  except:
    ip = 0
  return ip

# #### **1.3. "@" Symbol in URL** # 3.Checks the presence of @ in URL (Have_At)
# Checks for the presence of '@' symbol in the URL. Using “@” symbol in the URL leads the browser to ignore everything preceding the “@” symbol and the real address often follows the “@” symbol.

# If the URL has '@' symbol, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).

def haveAtSign(url):
  if "@" in url:
    at = 1
  else:
    at = 0
  return at

# #### **# 1.4.Finding the length of URL and categorizing (URL_Length)
# Computes the length of the URL. Phishers can use long URL to hide the doubtful part in the address bar. In this project, if the length of the URL is greater than or equal 54 characters then the URL classified as phishing otherwise legitimate.

# If the length of URL >= 54 , the value assigned to this feature is 1 (phishing) or else 0 (legitimate).

def getLength(url):
  if len(url) < 54:
    length = 0
  else:
    length = 1
  return length

# #### **1.5.Gives number of '/' in URL (URL_Depth)
# Computes the depth of the URL. This feature calculates the number of sub pages in the given url based on the '/'.

# The value of feature is a numerical based on the URL.

def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth

# #### *1.6 Checking for redirection'//' in the url (Redirection)
# Checks the presence of "//" in the URL. The existence of “//” within the URL path means that the user will be redirected to another website. The location of the “//” in URL is computed. We find that if the URL starts with “HTTP”, that means the “//” should appear in the sixth position. However, if the URL employs “HTTPS” then the “//” should appear in seventh position.

# If the "//" is anywhere in the URL apart from after the protocal, thee value assigned to this feature is 1 (phishing) or else 0 (legitimate).

def redirection(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 1
    else:
      return 0
  else:
    return 0

# #### **1.7.Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
# Checks for the presence of "http/https" in the domain part of the URL. The phishers may add the “HTTPS” token to the domain part of a URL in order to trick users.

# If the URL has "http/https" in the domain part, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).

def httpDomain(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 1
  else:
    return 0

# #### **1.8. Checking for Shortening Services in URL (Tiny_URL)
# URL shortening is a method on the “World Wide Web” in which a URL may be made considerably smaller in length and still lead to the required webpage. This is accomplished by means of an “HTTP Redirect” on a domain name that is short, which links to the webpage that has a long URL.

# If the URL is using Shortening Services, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).

shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

def tinyURL(url):
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0

# #### **# 1.9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
# Checking the presence of '-' in the domain part of URL. The dash symbol is rarely used in legitimate URLs. Phishers tend to add prefixes or suffixes separated by (-) to the domain name so that users feel that they are dealing with a legitimate webpage.

# If the URL has '-' symbol in the domain part of the URL, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).

def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1            # phishing
    else:
        return 0            # legitimate

#2.2 HTML and JavaScript based Features

#IFrame Redirection
#Status Bar Customization
#Disabling Right Click
#Website Forwarding

#2.1. IFrame Redirection(iFrame)
#IFrame is an HTML tag used to display an additional webpage into one that is currently shown. Phishers can make use of the “iframe” tag and make it invisible i.e. without frame borders. In this regard, phishers make use of the “frameBorder” attribute which causes the browser to render a visual delineation.

#If the iframe is empty or repsonse is not found then, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).

def iframe(response):
  if response == "":
      return 1
  else:
      if re.findall(r"[|]", response.text):
          return 0
      else:
          return 1

#2.2. Status Bar Customization. Checks the effect of mouse over on status bar (Mouse_Over)
#Phishers may use JavaScript to show a fake URL in the status bar to users. To extract this feature, we must dig-out the webpage source code, particularly the “onMouseOver” event, and check if it makes any changes on the status bar

#If the response is empty or onmouseover is found then, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).

def mouseOver(response):
    if response == "":
        return 1
    else:
        matches = re.findall('<a\s.*?onmouseover\s*=.*?>', response.text, re.IGNORECASE)
        if matches:
            return 1
        else:
            return 0

#3.3.3. Disabling Right Click
#Phishers use JavaScript to disable the right-click function, so that users cannot view and save the webpage source code. This feature is treated exactly as “Using onMouseOver to hide the Link”. Nonetheless, for this feature, we will search for event “event.button==2” in the webpage source code and check if the right click is disabled.

# 17.Checks the status of the right click attribute (Right_Click)
#returns 1 for a legitimate website and 0 for phising website
def rightClick(response):
    if response == "":
        return 1
    else:
        # Check for event.button==2
        if re.search(r"event\.button==2", response.text, re.IGNORECASE):
            return 0

        # Check for oncontextmenu attribute
        if re.search(r'oncontextmenu="return\s*false"', response.text, re.IGNORECASE):
            return 0
        elif re.search(r'oncontextmenu="\s*false"', response.text, re.IGNORECASE):
            return 0
        elif re.search(r'oncontextmenu\s*=[\s]*\w+\s*=\s*false', response.text, re.IGNORECASE):
            return 0

        # Check for onmousedown event
        if re.search(r'onmousedown=["\']\w+\s*=\s*false["\']', response.text, re.IGNORECASE):
            return 0

        # Check for document.oncontextmenu
        if re.search(r'document\.oncontextmenu\s*=[\s]*\w+\s*=\s*false', response.text, re.IGNORECASE):
            return 0

        # Check for enabling right-click
        if re.search(r'oncontextmenu="\s*null\s*"', response.text, re.IGNORECASE):
            return 1
        elif re.search(r'oncontextmenu=[\s]*function\s*\(\)\s*\{\s*return\s*true\s*\}\s*', response.text, re.IGNORECASE):
            return 1

        # If no suspicious behavior is found, return 1
        return 1

#3.3.4. Website Forwarding
#The fine line that distinguishes phishing websites from legitimate ones is how many times a website has been redirected. In our dataset, we find that legitimate websites have been redirected one time max. On the other hand, phishing websites containing this feature have been redirected at least 4 times.

# 18.Checks the number of forwardings (Web_Forwards)

def forwarding(response):
  if response == "":
    return 1
  else:
    if len(response.history) <= 2:
      return 0
    else:
      return 1

# ## **4. Computing URL Features**

# Create a list and a function that calls the other functions and stores all the features of the URL in the list. We will extract the features of each URL and append to this list.

#Function to extract features
def featureExtraction(url,label):

  features = []
  #Address bar based features (10)
  #features.append(getDomain(url))
  features.append(havingIP(url))
  features.append(haveAtSign(url))
  features.append(getLength(url))
  features.append(getDepth(url))
  features.append(redirection(url))
  features.append(httpDomain(url))
  features.append(tinyURL(url))
  features.append(prefixSuffix(url))
  
  try:
    response = requests.get(url, verify=False)
  except:
    response = ""
  features.append(iframe(response))
  features.append(mouseOver(response))
  features.append(rightClick(response))
  features.append(forwarding(response))
  
  features.append(label)
  return features

# Define feature names
feature_names = ['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection', 
                 'https_Domain', 'TinyURL', 'Prefix/Suffix', 'iFrame', 'Mouse_Over', 
                 'Right_Click', 'Web_Forwards', 'Label']

#Extracting the features & storing them in a list
legi_features = []
label = 0
chunk_size = 10
for i in range(0, len(data0), chunk_size):
    urls = data0['URL'][i:i+chunk_size]
    legi_features = []
    for url in urls:
        legi_features.append(featureExtraction(url, label))
    
    #converting the list to dataframe
    feature_names= ['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection', 
                 'https_Domain', 'TinyURL', 'Prefix/Suffix', 'iFrame', 'Mouse_Over', 
                 'Right_Click', 'Web_Forwards', 'Label']
    
    legitimate = pd.DataFrame(legi_features, columns=feature_names)
    legitimate.to_csv('Legitimate_features_final.csv', index=False)#, mode='a', header=False
    print(f"Completed chunk {i//chunk_size+1} of {len(data0)//chunk_size}.")


#converting the list to dataframe
#feature_names = ['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection', 
#                 'https_Domain', 'TinyURL', 'Prefix/Suffix', 'iFrame', 'Mouse_Over', 
#                 'Right_Click', 'Web_Forwards', 'Label']

#legitimate = pd.DataFrame(legi_features, columns= feature_names)
#print(legitimate.head(20))

# Storing the extracted legitimate URLs features to csv file
#legitimate.to_csv('Legitimate_features.csv', index= False)