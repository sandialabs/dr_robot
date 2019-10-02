# Usage

## Gather

To gather data simply run the following command:

```
drrobot gather --help
usage: drrobot gather [-h] [-aqua] [-sub] [-turbo] [-brute] [-sfinder]
                      [-knock] [-amass] [-recon] [-altdns] [-anubis] [-ctexpo]
                      [-ctfr] [-pdlist] [-shodan] [-arin] [-hack] [-dump]
                      [-virus] [--ignore IGNORE] [--headers]
                      domain

drrobot gather <tool> <domain>
...

```


## Inspection

Inspection is not a passive usage. It will run a tool that uses the aggregated information to grab screenshots for manual enumeration.

```
drrobot inspect --help
usage: drrobot inspect [-h] [-http] [-eye] [-nmapscreen] [-webscreen] domain

positional arguments:
  domain                Domain to run scan against

optional arguments:
  -h, --help            show this help message and exit
  -http, --HTTPScreenshot
                        Post enumeration tool for screen grabbing websites.
                        All images will be downloaded to outfile:
                        httpscreenshot.tar and unpacked httpscreenshots
  -eye, --Eyewitness    Post enumeration tool for screen grabbing websites.
                        All images will be downloaded to outfile:
                        Eyewitness.tar and unpacked in Eyewitness
  -nmapscreen, --Nmap   Post enumeration tool for screen grabbing websites.
                        (Chrome is not installed in the dockerfile due.
                        Options are chromium-browser/firefox/wkhtmltoimage)
  -webscreen, --Webscreenshot
                        Post enumeration tool for screen grabbing websites.
                        (Chrome is not installed in the dockerfile due.
                        Options are chromium-browser/firefox/wkhtmltoimage)
```

## Upload

Upload to Slack/Mattermost

```
drrobot upload --help
usage: drrobot upload [-h] [-matter] [-slack] filepath

positional arguments:
  filepath              Filepath to the folder containing imagesto upload.
                        This is relative to the domain specified. By default
                        this will be the path to the output folder

optional arguments:
  -h, --help            show this help message and exit
  -matter, --Mattermost
                        Mattermost server
  -slack, --Slack       Slack server
```

## Rebuild

Rebuild will use the config file to determine what files to use when aggregating data. This will update the database with new information. This does not recreate the aggregated files

```
drrobot rebuild --help
usage: drrobot rebuild [-h] [-f [FILES [FILES ...]]] [--headers] domain

positional arguments:
  domain                Domain to dump output of

optional arguments:
  -h, --help            show this help message and exit
  -f [FILES [FILES ...]], --files [FILES [FILES ...]]
                        Additional files to supply outside of the config file
  --headers             Rebuild with headers
```

## Dumpdb
Dump the database to aggregated files and the header files as well

```
drrobot dumpdb --help
usage: drrobot dumpdb [-h] domain

positional arguments:
  domain      Domain to show data for

optional arguments:
  -h, --help  show this help message and exit
```

## Output
Generate output file as JSON or XML

```
drrobot output --help
usage: drrobot output [-h] [--output OUTPUT] {json,xml} domain

positional arguments:
  {json,xml}       Generate json file under outputs folder (format)
  domain           Domain to dump output of

optional arguments:
  -h, --help       show this help message and exit
  --output OUTPUT  Alternative location to create output file
```
