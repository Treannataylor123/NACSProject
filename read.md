# NACSProject

Title: NACS-Not Another CyberSite

Description: The purpose of this website is to promote nontechincial users to secure data and assets
on their personal systems and networks. After doing a bit of research I discovered the most common vulnerabilties in 
of cyber attacks against non technical people are through malicious code and ransomeware from either downloaded files or 
unsecure sites. Therefore, I developed a web application to promote non-technical users to the protect cyber information. The features includes
a file scanner for malicious detection, url scanner for unsecure blacklisted sites, 
informational tips on protecting home, tool recommendations,  and information on the top Malicious threats for 
the most common operating systems.

The goal in developing this application was to be more technical on the back-end in the developemnet of tools and features, and simplicity on the UI for user simplicity. In addition, this is a full stacked application using Jquery, bootstrap, css, jinga, and Html on the front end and  Python server, and postcrest database on the back-end. For the file detection scanner, I used Yara to create the rules to run against the uploaded files. Yara is a utiltily used primarily for malware research and detection. For the url scanner
I used google Safebrowsing LookupApi. This api runs the urls against Google's blacklist service that contains thousands of detected unsafe sites across
the web. I also used Scrapy for web scraping form the reseached sites. The research done for the web application comes from from many resources such as Forbes, CIS, Norton, CISA, and 
more. In conclusion, there are many more frameworks, tools, and modules used to develop the overall functionality of 
the application. 
