# VirusTotal-Python-Tools
Just a small grouping of some tools for reuse made in python and using the free Virus Total API.

To use:
  Get an account on the virus total website and on your profile page, look for "My API Key"
  Copy and paste the key into the VIRUSTOTAL_API2_KEY = '' variable in script you plan on using.
  

VT_gui.py
  Widget with a single text field for short search jobs on a hash that prevents you from having to go online for the report.
  Just copy and paste a hash into the text box and press the enter key.
  You'll see a counter in the bottom corner of the box denoting the number of scanners that popped positive on the hash.
  
VT_search.py
Takes a list of hashes and generates a comma separated list of all the data it pulled on the hashes in the list.
