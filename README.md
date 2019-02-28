# bloodhound-users-json-parser.py
Parse bloodhound user json file to a cvs.

Currently the script only pulls and parses the following Active Directory user fields of interest:

`name,enabled,displayname,email,title,description`

## Usage
`python ./bloodhound-users-json-parser.py <bloodhound-users.json>`


## Examples
Parse and output to file:

`python ./bloodhound-users-json-parser.py bloodhound-users.json > parsed-users.csv`

View only enabled accounts (use list for pw guessing purposes):

`cat parsed-users.csv | grep True | cut -d "," -f 1`

View all emails only, sort alphabetically and remove any duplicates:

`cat parsed-users.csv | cut -d "," -f 4 | sort | uniq`

View unique account descriptions (any passwords in there?)

`cat parsed-users.csv | cut -d "," -f 6 | sort | uniq`





# masscan_parse.py
Parse masscan xml to ip:port format.

## Usage
`python ./masscan_parser.py <results.xml>`
