#!/usr/bin/env python
# Python 3
# waymore - by @Xnl-h4ck3r: Find way more from the Wayback Machine (also get links from Common Crawl, AlienVault OTX, URLScan, VirusTotal and Intelligence X)
# Full help here: https://github.com/xnl-h4ck3r/waymore/blob/main/README.md
# Good luck and good hunting! If you really love the tool (or any others), or they helped you find an awesome bounty, consider BUYING ME A COFFEE! (https://ko-fi.com/xnlh4ck3r) ☕ (I could use the caffeine!)

import argparse
import asyncio
import enum
import ipaddress
import json
import math
import multiprocessing.dummy as mp
import os
import pickle
import random
import re
import sys
import threading
from datetime import datetime, timedelta
from pathlib import Path
from signal import SIGINT, signal
from typing import Optional
from urllib.parse import unquote, urlparse

import requests
import tldextract
import yaml
from requests.adapters import HTTPAdapter, Retry
from requests.exceptions import ConnectionError
from requests.utils import quote
from termcolor import colored
from urllib3.poolmanager import PoolManager

try:
    from . import __version__
except Exception:
    pass

# Try to import psutil to show memory usage
try:
    import psutil
except Exception:
    currentMemUsage = -1
    maxMemoryUsage = -1
    currentMemPercent = -1
    maxMemoryPercent = -1


# Creating stopProgram enum
class StopProgram(enum.Enum):
    SIGINT = 1
    WEBARCHIVE_PROBLEM = 2
    MEMORY_THRESHOLD = 3


stopProgram = None

# Global variables
linksFound = set()
linkMimes = set()
inputValues = set()
argsInput = ""
isInputFile = False
stopProgramCount = 0
stopSource = False
stopSourceWayback = False
stopSourceCommonCrawl = False
stopSourceAlienVault = False
stopSourceURLScan = False
stopSourceVirusTotal = False
stopSourceIntelx = False
stopSourceGhostArchive = False
successCount = 0
failureCount = 0
fileCount = 0
totalFileCount = 0
totalResponses = 0
totalPages = 0
indexFile = None
continueRespFile = None
continueRespFileURLScan = None
continueRespFileGhostArchive = None
inputIsDomainANDPath = False
inputIsSubDomain = False
subs = "*."
path = ""
waymorePath = ""
terminalWidth = 135
maxMemoryUsage = 0
currentMemUsage = 0
maxMemoryPercent = 0
currentMemPercent = 0
process = None
current_response = None
current_session = None
# Event used to interrupt long sleeps (e.g., rate-limit waits) when SIGINT is received
interrupt_event = threading.Event()
HTTP_ADAPTER = None
HTTP_ADAPTER_CC = None
checkWayback = 0
checkCommonCrawl = 0
checkAlienVault = 0
checkURLScan = 0
checkVirusTotal = 0
checkIntelx = 0
checkGhostArchive = 0
argsInputHostname = ""
responseOutputDirectory = ""
urlscanRequestLinks = set()
intelxAPIIssue = False
linkCountWayback = 0
linkCountCommonCrawl = 0
linkCountAlienVault = 0
linkCountURLScan = 0
linkCountVirusTotal = 0
linkCountIntelx = 0
linkCountGhostArchive = 0
linksFoundCommonCrawl = set()
linksFoundAlienVault = set()
linksFoundURLScan = set()
linksFoundVirusTotal = set()
linksFoundIntelx = set()
linksFoundGhostArchive = set()
ghostArchiveRequestLinks = set()

# Thread lock for protecting shared state during concurrent operations
links_lock = threading.Lock()

# Shared state for link collection across all sources
linksFound = set()
linkMimes = set()
extraWarcLinks = set()  # Track extra URLs found in WARC files for mode B

# Source Provider URLs
WAYBACK_URL = "https://web.archive.org/cdx/search/cdx?url={DOMAIN}{COLLAPSE}&fl=timestamp,original,mimetype,statuscode,digest"
CCRAWL_INDEX_URL = "https://index.commoncrawl.org/collinfo.json"
ALIENVAULT_URL = "https://otx.alienvault.com/api/v1/indicators/{TYPE}/{DOMAIN}/url_list?limit=500"
URLSCAN_URL = "https://urlscan.io/api/v1/search/?q=domain:{DOMAIN}{DATERANGE}&size=10000"
URLSCAN_DOM_URL = "https://urlscan.io/dom/"
VIRUSTOTAL_URL = "https://www.virustotal.com/vtapi/v2/domain/report?apikey={APIKEY}&domain={DOMAIN}"
# Paid endpoint first, free endpoint as fallback
INTELX_BASES = ["https://2.intelx.io", "https://free.intelx.io"]
GHOSTARCHIVE_URL = "https://ghostarchive.org/search?term={DOMAIN}&page="
GHOSTARCHIVE_DOM_URL = "https://ghostarchive.org"

intelx_tls = threading.local()


def initIntelxTls():
    """Initialize thread-local storage for IntelX if not already done."""
    pass


def setIntelxBase(base: str):
    """Update IntelX URLs to use the provided base (thread-local)."""
    pass


def chooseIntelxBase(api_key: str) -> Optional[requests.Response]:
    """
    Probe IntelX endpoints in order (paid, then free) and set the first that works.
    Returns the last response (or None) so callers can inspect status/JSON.
    """
    pass


# User Agents to use when making requests, chosen at random
USER_AGENT = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 Edg/99.0.1150.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    "Mozilla/5.0 (iPad; CPU OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D257 Safari/9537.53",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
]


class SourceAddressAdapter(HTTPAdapter):
    """
    HTTPAdapter that binds outbound connections to a specific source IP address
    """

    def __init__(self, source_ip=None, *args, **kwargs):
        self.source_ip = source_ip
        super().__init__(*args, **kwargs)




# The default maximum number of responses to download
DEFAULT_LIMIT = 5000

# The default timeout for archived responses to be retrieved in seconds
DEFAULT_TIMEOUT = 30

# Exclusions used to exclude responses we will try to get from web.archive.org
DEFAULT_FILTER_URL = ".css,.jpg,.jpeg,.png,.svg,.img,.gif,.mp4,.flv,.ogv,.webm,.webp,.mov,.mp3,.m4a,.m4p,.scss,.tif,.tiff,.ttf,.otf,.woff,.woff2,.bmp,.ico,.eot,.htc,.rtf,.swf,.image,/image,/img,/css,/wp-json,/wp-content,/wp-includes,/theme,/audio,/captcha,/font,node_modules,/jquery,/bootstrap,/_incapsula_resource,.wmv,.wma,.asx,.avif"

# MIME Content-Type exclusions used to filter links and responses from web.archive.org through their API
DEFAULT_FILTER_MIME = "text/css,image/jpeg,image/jpg,image/png,image/svg+xml,image/gif,image/tiff,image/webp,image/bmp,image/vnd,image/x-icon,image/vnd.microsoft.icon,font/ttf,font/woff,font/woff2,font/x-woff2,font/x-woff,font/otf,audio/mpeg,audio/wav,audio/webm,audio/aac,audio/ogg,audio/wav,audio/webm,video/mp4,video/mpeg,video/webm,video/ogg,video/mp2t,video/webm,video/x-msvideo,video/x-flv,application/font-woff,application/font-woff2,application/x-font-woff,application/x-font-woff2,application/vnd.ms-fontobject,application/font-sfnt,application/vnd.android.package-archive,binary/octet-stream,application/octet-stream,application/x-font-ttf,application/x-font-otf,video/webm,video/3gpp,application/font-ttf,audio/mp3,audio/x-wav,image/pjpeg,audio/basic,application/font-otf,application/x-ms-application,application/x-msdownload,video/x-ms-wmv,image/x-png,video/quicktime,image/x-ms-bmp,font/opentype,application/x-font-opentype,application/x-woff,audio/aiff,video/x-ms-asf,audio/x-ms-wma,audio/wma,application/x-mplayer2,image/avif"

# Response code exclusions we will use to filter links and responses from web.archive.org through their API
DEFAULT_FILTER_CODE = "404,301,302"

# Used to filter out downloaded responses that could be custom 404 pages
REGEX_404 = r"<title>[^\<]*(404|not found)[^\<]*</title>"

# Keywords
DEFAULT_FILTER_KEYWORDS = "admin,login,logon,signin,signup,register,registration,dash,portal,ftp,panel,.js,api,robots.txt,graph,gql,config,backup,debug,db,database,git,cgi-bin,swagger,zip,rar,tar.gz,internal,jira,jenkins,confluence,atlassian,okta,corp,upload,delete,email,sql,create,edit,test,temp,cache,wsdl,log,payment,setting,mail,file,redirect,chat,billing,doc,trace,cp,ftp,gateway,import,proxy,dev,stage,stg,uat"

# Yaml config values
FILTER_URL = ""
FILTER_MIME = ""
MATCH_MIME = ""
FILTER_CODE = ""
MATCH_CODE = ""
FILTER_KEYWORDS = ""
URLSCAN_API_KEY = ""
CONTINUE_RESPONSES_IF_PIPED = True
WEBHOOK_DISCORD = ""
TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHAT_ID = ""
DEFAULT_OUTPUT_DIR = ""
INTELX_API_KEY = ""
SOURCE_IP = None

API_KEY_SECRET = "aHR0cHM6Ly95b3V0dS5iZS9kUXc0dzlXZ1hjUQ=="

# When -oijs is passed, and the downloaded responses are checked for scripts, files with these extensions will be ignored
INLINE_JS_EXCLUDE = [
    ".js",
    ".csv",
    ".xls",
    ".xlsx",
    ".doc",
    ".docx",
    ".pdf",
    ".msi",
    ".zip",
    ".gzip",
    ".gz",
    ".tar",
    ".rar",
    ".json",
]

# Binary file extensions that should be saved as raw bytes, not text
BINARY_EXTENSIONS = frozenset(
    [
        ".zip",
        ".gz",
        ".gzip",
        ".tar",
        ".rar",
        ".7z",
        ".bz2",
        ".xz",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".exe",
        ".msi",
        ".dll",
        ".bin",
        ".so",
        ".dmg",
        ".deb",
        ".rpm",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico",
        ".webp",
        ".svg",
        ".tiff",
        ".tif",
        ".mp3",
        ".mp4",
        ".wav",
        ".avi",
        ".mov",
        ".mkv",
        ".flv",
        ".wmv",
        ".webm",
        ".ogg",
        ".ttf",
        ".otf",
        ".woff",
        ".woff2",
        ".eot",
        ".class",
        ".jar",
        ".war",
        ".ear",
        ".pyc",
        ".pyo",
        ".o",
        ".a",
        ".lib",
        ".iso",
        ".img",
        ".sqlite",
        ".db",
        ".mdb",
        ".swf",
        ".fla",
    ]
)

# Binary MIME types that should be saved as raw bytes, not text
BINARY_MIME_TYPES = frozenset(
    [
        "application/zip",
        "application/x-zip-compressed",
        "application/x-gzip",
        "application/gzip",
        "application/x-tar",
        "application/x-rar-compressed",
        "application/x-7z-compressed",
        "application/x-bzip2",
        "application/x-xz",
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/x-msdownload",
        "application/x-msi",
        "application/x-dosexec",
        "application/octet-stream",
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/bmp",
        "image/x-icon",
        "image/webp",
        "image/tiff",
        "audio/mpeg",
        "audio/wav",
        "audio/ogg",
        "audio/webm",
        "video/mp4",
        "video/avi",
        "video/quicktime",
        "video/x-msvideo",
        "video/x-matroska",
        "video/webm",
        "video/ogg",
        "font/ttf",
        "font/otf",
        "font/woff",
        "font/woff2",
        "application/x-font-ttf",
        "application/x-font-otf",
        "application/font-woff",
        "application/font-woff2",
        "application/java-archive",
        "application/x-java-class",
        "application/x-shockwave-flash",
        "application/x-sqlite3",
        "application/x-iso9660-image",
    ]
)


def isBinaryContent(contentBytes, contentType, url=""):
    """
    Determine if content should be treated as binary based on actual content, Content-Type, and URL.

    Priority (highest to lowest):
    1. Content inspection - check for text signatures (most reliable)
    2. Content-Type header
    3. URL extension (least reliable - archive might have captured an HTML error page)

    Args:
        contentBytes: The raw response bytes (at least first 100 bytes)
        contentType: The Content-Type header value
        url: The URL (optional, used as fallback)

    Returns True if content is binary and should be saved as raw bytes.
    """
    pass


# Get memory usage for
def getMemory():

    global currentMemUsage, currentMemPercent, maxMemoryUsage, maxMemoryPercent, stopProgram, process

    try:
        currentMemUsage = process.memory_info().rss
        currentMemPercent = math.ceil(psutil.virtual_memory().percent)
        if currentMemUsage > maxMemoryUsage:
            maxMemoryUsage = currentMemUsage
        if currentMemPercent > maxMemoryPercent:
            maxMemoryPercent = currentMemPercent
        if currentMemPercent > args.memory_threshold:
            stopProgram = StopProgram.MEMORY_THRESHOLD
    except Exception:
        pass


# Convert bytes to human readable form
def humanReadableSize(size, decimal_places=2):
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if size < 1024.0 or unit == "PB":
            break
        size /= 1024.0
    return f"{size:.{decimal_places}f} {unit}"


# Display stats if -v argument was chosen
def processStats():
    if maxMemoryUsage > 0:
        write("MAX MEMORY USAGE: " + humanReadableSize(maxMemoryUsage))
    elif maxMemoryUsage < 0:
        write('MAX MEMORY USAGE: To show memory usage, run "pip install psutil"')
    if maxMemoryPercent > 0:
        write(
            "MAX TOTAL MEMORY: "
            + str(maxMemoryPercent)
            + "% (Threshold "
            + str(args.memory_threshold)
            + "%)"
        )
    elif maxMemoryUsage < 0:
        write('MAX TOTAL MEMORY: To show total memory %, run "pip install psutil"')
    write()


def write(text="", pipe=False):
    # Only send text to stdout if the tool isn't piped to pass output to something else,
    # or if the tool has been piped and the pipe parameter is True
    # AND if --stream is NOT active OR if it is active but we are explicitly piping (e.g. for URLs)
    if (sys.stdout.isatty() or (not sys.stdout.isatty() and pipe)) and (
        not (args.stream and args.mode == "U") or (args.stream and args.mode == "U" and pipe)
    ):
        # If it has carriage return in the string, don't add a newline
        if text.find("\r") > 0:
            sys.stdout.write(text)
        else:
            sys.stdout.write(text + "\n")


def writerr(text="", pipe=False):
    # If --stream is active and mode is 'U', and verbose is NOT true, suppress output.
    # Otherwise, use the existing logic.
    if args.stream and args.mode == "U" and not args.verbose:
        pass  # Suppress output
    else:
        # Original logic: write to stdout if interactive, else stderr
        if sys.stdout.isatty():
            if text.find("\r") > 0:
                sys.stdout.write(text)
            else:
                sys.stdout.write(text + "\n")
        else:
            if text.find("\r") > 0:
                sys.stderr.write(text)
            else:
                sys.stderr.write(text + "\n")


def showVersion():
    global HTTP_ADAPTER
    try:
        try:
            session = requests.Session()
            if HTTP_ADAPTER is not None:
                session.mount("https://", HTTP_ADAPTER)
                session.mount("http://", HTTP_ADAPTER)
            resp = session.get(
                "https://raw.githubusercontent.com/xnl-h4ck3r/waymore/main/waymore/__init__.py",
                timeout=3,
            )
        except Exception:
            write("Current waymore version " + __version__ + " (unable to check if latest)\n")
        if __version__ == resp.text.split("=")[1].replace('"', "").strip():
            write(
                "Current waymore version " + __version__ + " (" + colored("latest", "green") + ")\n"
            )
        else:
            write(
                "Current waymore version " + __version__ + " (" + colored("outdated", "red") + ")\n"
            )
    except Exception:
        pass


def showBanner():
    write()
    write(colored(" _ _ _       _   _ ", "red") + "____                    ")
    write(colored("| | | |_____| | | ", "red") + r"/    \  ___   ____ _____ ")
    write(colored("| | | (____ | | | ", "red") + r"| | | |/ _ \ / ___) ___ |")
    write(colored("| | | / ___ | |_| ", "red") + "| | | | |_| | |   | |_| |")
    write(colored(r" \___/\_____|\__  ", "red") + r"|_|_|_|\___/| |   | ____/")
    write(
        colored("            (____/ ", "red") + colored("  by Xnl-h4ck3r ", "magenta") + r" \_____)"
    )
    try:
        currentDate = datetime.now().date()
        if currentDate.month == 12 and currentDate.day in (24, 25):
            write(
                colored(
                    "            *** 🎅 HAPPY CHRISTMAS! 🎅 ***",
                    "green",
                    attrs=["blink"],
                )
            )
        elif currentDate.month == 10 and currentDate.day == 31:
            write(colored("            *** 🎃 HAPPY HALLOWEEN! 🎃 ***", "red", attrs=["blink"]))
        elif currentDate.month == 1 and currentDate.day in (1, 2, 3, 4, 5):
            write(
                colored(
                    "            *** 🥳 HAPPY NEW YEAR!! 🥳 ***",
                    "yellow",
                    attrs=["blink"],
                )
            )
    except Exception:
        pass
    write()
    showVersion()


def verbose():
    """
    Functions used when printing messages dependant on verbose option
    """
    return args.verbose


def handler(signal_received, frame):
    """
    This function is called if Ctrl-C is called by the user
    An attempt will be made to try and clean up properly
    """
    pass


def showOptions():
    """
    Show the chosen options and config settings
    """
    global inputIsDomainANDPath, argsInput, isInputFile, INTELX_API_KEY, SOURCE_IP

    try:
        write(colored("Selected config and settings:", "cyan"))

        if isInputFile:
            inputArgDesc = "-i <FILE: current line>: "
        else:
            inputArgDesc = "-i: "
        if inputIsDomainANDPath:
            write(
                colored(inputArgDesc + argsInput, "magenta")
                + colored(" The target URL to search for.", "white")
            )
        else:  # input is a domain
            write(
                colored(inputArgDesc + argsInput, "magenta")
                + colored(" The target domain to search for.", "white")
            )

        if args.mode == "U":
            write(
                colored("-mode: " + args.mode, "magenta")
                + colored(" Only URLs will be retrieved for the input.", "white")
            )
        elif args.mode == "R":
            write(
                colored("-mode: " + args.mode, "magenta")
                + colored(" Only Responses will be downloaded for the input.", "white")
            )
        elif args.mode == "B":
            write(
                colored("-mode: " + args.mode, "magenta")
                + colored(
                    " URLs will be retrieved AND Responses will be downloaded for the input.",
                    "white",
                )
            )

        if args.config is not None:
            write(
                colored("-c: " + args.config, "magenta")
                + colored(" The path of the YML config file.", "white")
            )

        if args.no_subs:
            write(
                colored("-n: " + str(args.no_subs), "magenta")
                + colored(" Sub domains are excluded in the search.", "white")
            )
        else:
            write(
                colored("-n: " + str(args.no_subs), "magenta")
                + colored(" Sub domains are included in the search.", "white")
            )

        providers = ""
        if not args.xwm:
            providers = providers + "Wayback, "
        if not args.xcc:
            providers = providers + "CommonCrawl, "
        if not args.xav:
            providers = providers + "Alien Vault OTX, "
        if not args.xus:
            providers = providers + "URLScan, "
        if not args.xvt:
            providers = providers + "VirusTotal, "
        # Only show Intelligence X if the API key wa provided
        if not args.xix and INTELX_API_KEY != "":
            providers = providers + "Intelligence X, "
        if providers == "":
            providers = "None"
        write(
            colored("Providers: " + str(providers.strip(", ")), "magenta")
            + colored(" Which providers to check for URLs.", "white")
        )

        if not args.xcc:
            if args.lcc == 0 and args.from_date is None and args.to_date is None:
                write(
                    colored("-lcc: " + str(args.lcc), "magenta")
                    + colored(" Search ALL Common Crawl index collections.", "white")
                )
            else:
                if args.from_date is None and args.to_date is None:
                    write(
                        colored("-lcc: " + str(args.lcc), "magenta")
                        + colored(
                            " The number of latest Common Crawl index collections to be searched.",
                            "white",
                        )
                    )
                else:
                    if args.lcc != 0:
                        write(
                            colored("-lcc: " + str(args.lcc), "magenta")
                            + colored(
                                " The number of latest Common Crawl index collections to be searched within the specified date range (-to and -from).",
                                "white",
                            )
                        )

        if URLSCAN_API_KEY == "":
            write(
                colored("URLScan API Key:", "magenta")
                + colored(
                    " {none} - You can get a FREE or paid API Key at https://urlscan.io/user/signup which will let you get more back, and quicker.",
                    "white",
                )
            )
        else:
            write(colored("URLScan API Key: ", "magenta") + colored(URLSCAN_API_KEY))

        if VIRUSTOTAL_API_KEY == "":
            write(
                colored("VirusTotal API Key:", "magenta")
                + colored(
                    " {none} - You can get a FREE or paid API Key at https://www.virustotal.com/gui/join-us which will let you get some extra URLs.",
                    "white",
                )
            )
        else:
            write(colored("VirusTotal API Key: ", "magenta") + colored(VIRUSTOTAL_API_KEY))

        if INTELX_API_KEY == "":
            write(
                colored("Intelligence X API Key:", "magenta")
                + colored(
                    " {none} - You require a Academia or Paid API Key from https://intelx.io/product",
                    "white",
                )
            )
        else:
            write(colored("Intelligence X API Key: ", "magenta") + colored(INTELX_API_KEY))

        if args.mode in ["U", "B"]:
            if args.output_urls != "":
                write(
                    colored("-oU: " + str(args.output_urls), "magenta")
                    + colored(" The name of the output file for URL links.", "white")
                )
            write(
                colored("-ow: " + str(args.output_overwrite), "magenta")
                + colored(
                    " Whether the URL output file will be overwritten if it already exists. If False (default), it will be appended to, and duplicates removed.",
                    "white",
                )
            )
            write(
                colored("-nlf: " + str(args.new_links_file), "magenta")
                + colored(
                    ' Whether the URL output file ".new" version will also be written. It will include only new links found for the same target on subsequent runs. This can be used for continuous monitoring of a target.',
                    "white",
                )
            )

        if args.mode in ["R", "B"]:
            if args.output_responses != "":
                write(
                    colored("-oR: " + str(args.output_responses), "magenta")
                    + colored(
                        " The directory to store archived responses and index file.",
                        "white",
                    )
                )
            if args.limit == 0:
                write(
                    colored("-l: " + str(args.limit), "magenta")
                    + colored(" Save ALL responses found.", "white")
                )
            else:
                if args.limit > 0:
                    write(
                        colored("-l: " + str(args.limit), "magenta")
                        + colored(
                            " Only save the FIRST " + str(args.limit) + " responses found.",
                            "white",
                        )
                    )
                else:
                    write(
                        colored("-l: " + str(args.limit), "magenta")
                        + colored(
                            " Only save the LAST " + str(abs(args.limit)) + " responses found.",
                            "white",
                        )
                    )

            if args.capture_interval == "h":
                write(
                    colored("-ci: " + args.capture_interval, "magenta")
                    + colored(
                        " Get at most 1 archived response per hour from Wayback Machine (archive.org)",
                        "white",
                    )
                )
            elif args.capture_interval == "d":
                write(
                    colored("-ci: " + args.capture_interval, "magenta")
                    + colored(
                        " Get at most 1 archived response per day from Wayback Machine (archive.org)",
                        "white",
                    )
                )
            elif args.capture_interval == "m":
                write(
                    colored("-ci: " + args.capture_interval, "magenta")
                    + colored(
                        " Get at most 1 archived response per month from Wayback Machine (archive.org)",
                        "white",
                    )
                )
            elif args.capture_interval == "none":
                write(
                    colored("-ci: " + args.capture_interval, "magenta")
                    + colored(
                        " There will not be any filtering based on the capture interval.",
                        "white",
                    )
                )

            if args.url_filename:
                write(
                    colored("-url-filename: " + str(args.url_filename), "magenta")
                    + colored(
                        " The filenames of downloaded responses wil be set to the URL rather than the hash value of the response.",
                        "white",
                    )
                )

            write(
                colored("-oijs: " + str(args.output_inline_js), "magenta")
                + colored(
                    " Whether the combined JS of all responses will be written to one or more files.",
                    "white",
                )
            )

        if args.from_date is not None:
            write(
                colored("-from: " + str(args.from_date), "magenta")
                + colored(
                    " The date/time to get data from.",
                    "white",
                )
                + colored(
                    " NOTE: All results will still be returned from Intelligence X, and all sub domains from Virus Total, because these cannot be filtered by date.",
                    "yellow",
                )
            )

        if args.to_date is not None:
            write(
                colored("-to: " + str(args.to_date), "magenta")
                + colored(
                    " The date/time to get data up to.",
                    "white",
                )
                + colored(
                    " NOTE: All results will still be returned from Intelligence X, and all sub domains from Virus Total, because these cannot be filtered by date.",
                    "yellow",
                )
            )

        write(
            colored("-f: " + str(args.filter_responses_only), "magenta")
            + colored(
                " If True, the initial links from wayback machine will not be filtered, only the responses that are downloaded will be filtered. It maybe useful to still see all available paths even if you don't want to check the file for content.",
                "white",
            )
        )
        if args.keywords_only is not None and args.keywords_only != "#CONFIG":
            write(
                colored("-ko: " + str(args.keywords_only), "magenta")
                + colored(" Only get results that match the given Regex.", "white")
            )

        write(
            colored("-lr: " + str(args.limit_requests), "magenta")
            + colored(
                " The limit of requests made per source when getting links. A value of 0 (Zero) means no limit is applied.",
                "white",
            )
        )
        if args.mc:
            write(
                colored("-mc: " + str(args.mc), "magenta")
                + colored(
                    " Only retrieve URLs and Responses that match these HTTP Status codes.",
                    "white",
                )
            )
        else:
            if args.fc:
                write(
                    colored("-fc: " + str(args.fc), "magenta")
                    + colored(
                        " Don't retrieve URLs and Responses that match these HTTP Status codes.",
                        "white",
                    )
                )
        if not args.mc and args.fc:
            write(colored("Response Code exclusions: ", "magenta") + colored(FILTER_CODE))
        write(colored("Response URL exclusions: ", "magenta") + colored(FILTER_URL))

        if args.mt:
            write(
                colored("-mt: " + str(args.mt.lower()), "magenta")
                + colored(
                    " Only retrieve URLs and Responses that match these MIME Types.",
                    "white",
                )
                + colored(
                    " NOTE: This will NOT be applied to Alien Vault OTX, Virus Total and Intelligence X because they don't have the ability to filter on MIME Type. Sometimes URLScan does not have a MIME Type defined - these will always be included. Consider excluding sources if this matters to you",
                    "yellow",
                )
            )
        else:
            if args.ft:
                write(
                    colored("-ft: " + str(args.ft.lower()), "magenta")
                    + colored(
                        " Don't retrieve URLs and Responses that match these MIME Types.",
                        "white",
                    )
                    + colored(
                        " NOTE: This will NOT be applied to Alien Vault OTX, Virus Total and Intelligence X because they don't have the ability to filter on MIME Type. Sometimes URLScan does not have a MIME Type defined - these will always be included. Consider excluding sources if this matters to you",
                        "yellow",
                    )
                )
            else:
                write(
                    colored("MIME Type exclusions: ", "magenta")
                    + colored(FILTER_MIME)
                    + colored(
                        " Don't retrieve URLs and Responses that match these MIME Types.",
                        "white",
                    )
                    + colored(
                        " NOTE: This will NOT be applied to Alien Vault OTX, Virus Total and Intelligence X because they don't have the ability to filter on MIME Type. Sometimes URLScan does not have a MIME Type defined - these will always be included. Consider excluding sources if this matters to you",
                        "yellow",
                    )
                )

        if args.keywords_only and args.keywords_only == "#CONFIG":
            if FILTER_KEYWORDS == "":
                write(
                    colored("Keywords only: ", "magenta")
                    + colored(
                        "It looks like no keywords have been set in config.yml file.",
                        "red",
                    )
                )
            else:
                write(colored("Keywords only: ", "magenta") + colored(FILTER_KEYWORDS))

        if args.notify_discord:
            if WEBHOOK_DISCORD == "" or WEBHOOK_DISCORD == "YOUR_WEBHOOK":
                write(
                    colored("Discord Webhook: ", "magenta")
                    + colored(
                        "It looks like no Discord webhook has been set in config.yml file.",
                        "red",
                    )
                )
            else:
                write(colored("Discord Webhook: ", "magenta") + colored(WEBHOOK_DISCORD))

        if args.notify_telegram:
            if (
                TELEGRAM_BOT_TOKEN == ""
                or TELEGRAM_BOT_TOKEN == "YOUR_TOKEN"
                or TELEGRAM_CHAT_ID == ""
                or TELEGRAM_CHAT_ID == "YOUR_CHAT_ID"
            ):
                write(
                    colored("Telegram: ", "magenta")
                    + colored(
                        "It looks like Telegram Bot Token or Chat ID has not been set in config.yml file.",
                        "red",
                    )
                )
            else:
                write(colored("Telegram Bot Token: ", "magenta") + colored(TELEGRAM_BOT_TOKEN))
                write(colored("Telegram Chat ID: ", "magenta") + colored(TELEGRAM_CHAT_ID))

        write(colored("Default Output Directory: ", "magenta") + colored(str(DEFAULT_OUTPUT_DIR)))

        if args.regex_after is not None:
            write(
                colored("-ra: " + args.regex_after, "magenta")
                + colored(
                    " RegEx for filtering purposes against found links from all sources of URLs AND responses downloaded. Only positive matches will be output.",
                    "white",
                )
            )
        if args.mode in ["R", "B"]:
            write(
                colored("-t: " + str(args.timeout), "magenta")
                + colored(
                    " The number of seconds to wait for a an archived response.",
                    "white",
                )
            )
        if args.mode in ["R", "B"] or (args.mode == "U" and not args.xcc):
            write(
                colored("-p: " + str(args.processes), "magenta")
                + colored(" The number of parallel requests made per source.", "white")
            )
        write(
            colored("-r: " + str(args.retries), "magenta")
            + colored(
                " The number of retries for requests that get connection error or rate limited.",
                "white",
            )
        )

        if not args.xwm:
            write(
                colored("-wrlr: " + str(args.wayback_rate_limit_retry), "magenta")
                + colored(
                    " The number of minutes to wait for a rate limit pause on Wayback Machine (archive.org) instead of stopping with a 429 error.",
                    "white",
                )
            )
        if not args.xus:
            write(
                colored("-urlr: " + str(args.urlscan_rate_limit_retry), "magenta")
                + colored(
                    " The number of minutes to wait for a rate limit pause on URLScan.io instead of stopping with a 429 error.",
                    "white",
                )
            )

        # Only show --source-ip if it's explicitly configured
        if SOURCE_IP:
            write(
                colored("--source-ip: " + str(SOURCE_IP), "magenta")
                + colored(" Outbound requests will bind to this IP.", "white")
            )

        write()

    except Exception as e:
        writerr(colored("ERROR showOptions: " + str(e), "red"))


def getConfig():
    """
    Try to get the values from the config file, otherwise use the defaults
    """
    global FILTER_CODE, FILTER_MIME, FILTER_URL, FILTER_KEYWORDS, URLSCAN_API_KEY, VIRUSTOTAL_API_KEY, CONTINUE_RESPONSES_IF_PIPED, subs, path, waymorePath, inputIsDomainANDPath, HTTP_ADAPTER, HTTP_ADAPTER_CC, argsInput, terminalWidth, MATCH_CODE, WEBHOOK_DISCORD, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, DEFAULT_OUTPUT_DIR, MATCH_MIME, INTELX_API_KEY, SOURCE_IP
    try:

        # Set terminal width
        try:
            terminalWidth = os.get_terminal_size().columns
        except Exception:
            terminalWidth = 135

        # If the input doesn't have a / then assume it is a domain rather than a domain AND path
        if str(argsInput).find("/") < 0:
            path = "/*"
            inputIsDomainANDPath = False
        else:
            # If there is only one / and is the last character, remove it
            if str(argsInput).count("/") == 1 and str(argsInput)[-1:] == "/":
                argsInput = argsInput.replace("/", "")
                path = "/*"
                inputIsDomainANDPath = False
            else:
                path = "*"
                inputIsDomainANDPath = True

        # If the -no-subs argument was passed, don't include subs
        # Also, if a path is passed, the subs will not be used
        if args.no_subs or inputIsDomainANDPath:
            subs = ""

        # Try to get the config file values
        useDefaults = False
        try:
            # Get the path of the config file. If -c / --config argument is not passed, then it defaults to config.yml in the same directory as the run file
            if os.name == "nt":
                waymorePath = Path(os.path.join(os.getenv("APPDATA", ""), "waymore"))
            elif sys.platform == "darwin":
                waymorePath = Path(os.path.expanduser("~/Library/Application Support/waymore"))
            else:
                waymorePath = Path(os.path.expanduser("~/.config/waymore"))

            if args.config is None:
                configPath = waymorePath / "config.yml"
            else:
                configPath = Path(args.config)

            # If the config file doesn't exist, create the default one
            if not os.path.isfile(configPath):
                try:
                    # Make sure the directory exists
                    if configPath.parent != Path("."):
                        os.makedirs(configPath.parent, exist_ok=True)
                    # Create the default config content using the DEFAULT_* constants
                    defaultConfig = f"""FILTER_CODE: {DEFAULT_FILTER_CODE}
FILTER_MIME: {DEFAULT_FILTER_MIME}
FILTER_URL: {DEFAULT_FILTER_URL}
FILTER_KEYWORDS: {DEFAULT_FILTER_KEYWORDS}
URLSCAN_API_KEY:
VIRUSTOTAL_API_KEY:
CONTINUE_RESPONSES_IF_PIPED: True
WEBHOOK_DISCORD: YOUR_WEBHOOK
TELEGRAM_BOT_TOKEN: YOUR_TOKEN
TELEGRAM_CHAT_ID: YOUR_CHAT_ID
DEFAULT_OUTPUT_DIR:
INTELX_API_KEY:
SOURCE_IP:
"""
                    with open(configPath, "w", encoding="utf-8") as f:
                        f.write(defaultConfig)
                    writerr(
                        colored(
                            'Config file not found - created default config at "'
                            + str(configPath)
                            + '"',
                            "yellow",
                        )
                    )
                except Exception as e:
                    writerr(
                        colored(
                            "Config file not found, but failed to create default config file: "
                            + str(e),
                            "red",
                        )
                    )

            config = yaml.safe_load(open(configPath))
            try:
                FILTER_URL = config.get("FILTER_URL")
                if str(FILTER_URL) == "None":
                    writerr(
                        colored(
                            'No value for "FILTER_URL" in config.yml - default set',
                            "yellow",
                        )
                    )
                    FILTER_URL = ""
            except Exception:
                writerr(
                    colored(
                        'Unable to read "FILTER_URL" from config.yml - default set',
                        "red",
                    )
                )
                FILTER_URL = DEFAULT_FILTER_URL

            # If the argument -ft was passed, don't try to get from the config
            if args.ft:
                FILTER_MIME = args.ft.lower()
            else:
                try:
                    FILTER_MIME = config.get("FILTER_MIME")
                    if str(FILTER_MIME) == "None":
                        writerr(
                            colored(
                                'No value for "FILTER_MIME" in config.yml - default set',
                                "yellow",
                            )
                        )
                        FILTER_MIME = ""
                except Exception:
                    writerr(
                        colored(
                            'Unable to read "FILTER_MIME" from config.yml - default set',
                            "red",
                        )
                    )
                    FILTER_MIME = DEFAULT_FILTER_MIME

            # Set the match codes if they were passed
            if args.mt:
                MATCH_MIME = args.mt.lower()

            # If the argument -fc was passed, don't try to get from the config
            if args.fc:
                FILTER_CODE = args.fc
            else:
                try:
                    FILTER_CODE = str(config.get("FILTER_CODE"))
                    if str(FILTER_CODE) == "None":
                        writerr(
                            colored(
                                'No value for "FILTER_CODE" in config.yml - default set',
                                "yellow",
                            )
                        )
                        FILTER_CODE = ""
                except Exception:
                    writerr(
                        colored(
                            'Unable to read "FILTER_CODE" from config.yml - default set',
                            "red",
                        )
                    )
                    FILTER_CODE = DEFAULT_FILTER_CODE

            # Set the match codes if they were passed
            if args.mc:
                MATCH_CODE = args.mc

            try:
                URLSCAN_API_KEY = config.get("URLSCAN_API_KEY")
                if str(URLSCAN_API_KEY) == "None":
                    if not args.xus:
                        writerr(
                            colored(
                                'No value for "URLSCAN_API_KEY" in config.yml - consider adding (you can get a FREE api key at urlscan.io)',
                                "yellow",
                            )
                        )
                    URLSCAN_API_KEY = ""
            except Exception:
                writerr(
                    colored(
                        'Unable to read "URLSCAN_API_KEY" from config.yml - consider adding (you can get a FREE api key at urlscan.io)',
                        "red",
                    )
                )
                URLSCAN_API_KEY = ""

            try:
                VIRUSTOTAL_API_KEY = config.get("VIRUSTOTAL_API_KEY")
                if str(VIRUSTOTAL_API_KEY) == "None":
                    if not args.xvt:
                        writerr(
                            colored(
                                'No value for "VIRUSTOTAL_API_KEY" in config.yml - consider adding (you can get a FREE api key at virustotal.com)',
                                "yellow",
                            )
                        )
                    VIRUSTOTAL_API_KEY = ""
            except Exception:
                writerr(
                    colored(
                        'Unable to read "VIRUSTOTAL_API_KEY" from config.yml - consider adding (you can get a FREE api key at virustotal.com)',
                        "red",
                    )
                )
                VIRUSTOTAL_API_KEY = ""

            try:
                INTELX_API_KEY = config.get("INTELX_API_KEY")
                if str(INTELX_API_KEY) == "None":
                    INTELX_API_KEY = ""
            except Exception:
                INTELX_API_KEY = ""

            try:
                if args.source_ip:
                    SOURCE_IP = args.source_ip
                else:
                    cfg_source_ip = config.get("SOURCE_IP")
                    if str(cfg_source_ip) in ("None", "", "null"):
                        SOURCE_IP = None
                    else:
                        try:
                            ipaddress.ip_address(cfg_source_ip)
                            SOURCE_IP = str(cfg_source_ip)
                        except ValueError:
                            writerr(
                                colored(
                                    'Invalid "SOURCE_IP" value in config.yml - ignoring and using default routing',
                                    "yellow",
                                )
                            )
                            SOURCE_IP = None
            except Exception:
                SOURCE_IP = args.source_ip

            try:
                FILTER_KEYWORDS = config.get("FILTER_KEYWORDS")
                if str(FILTER_KEYWORDS) == "None":
                    writerr(
                        colored(
                            'No value for "FILTER_KEYWORDS" in config.yml - default set',
                            "yellow",
                        )
                    )
                    FILTER_KEYWORDS = ""
            except Exception:
                writerr(
                    colored(
                        'Unable to read "FILTER_KEYWORDS" from config.yml - default set',
                        "red",
                    )
                )
                FILTER_KEYWORDS = ""

            try:
                CONTINUE_RESPONSES_IF_PIPED = config.get("CONTINUE_RESPONSES_IF_PIPED")
                if str(CONTINUE_RESPONSES_IF_PIPED) == "None":
                    writerr(
                        colored(
                            'No value for "CONTINUE_RESPONSES_IF_PIPED" in config.yml - default set',
                            "yellow",
                        )
                    )
                    CONTINUE_RESPONSES_IF_PIPED = True
            except Exception:
                writerr(
                    colored(
                        'Unable to read "CONTINUE_RESPONSES_IF_PIPED" from config.yml - default set',
                        "red",
                    )
                )
                CONTINUE_RESPONSES_IF_PIPED = True

            if args.notify_discord:
                try:
                    WEBHOOK_DISCORD = config.get("WEBHOOK_DISCORD")
                    if str(WEBHOOK_DISCORD) == "None" or str(WEBHOOK_DISCORD) == "YOUR_WEBHOOK":
                        writerr(
                            colored(
                                'No value for "WEBHOOK_DISCORD" in config.yml - default set',
                                "yellow",
                            )
                        )
                        WEBHOOK_DISCORD = ""
                except Exception:
                    writerr(
                        colored(
                            'Unable to read "WEBHOOK_DISCORD" from config.yml - default set',
                            "red",
                        )
                    )
                    WEBHOOK_DISCORD = ""

            if args.notify_telegram:
                try:
                    TELEGRAM_BOT_TOKEN = config.get("TELEGRAM_BOT_TOKEN")
                    if str(TELEGRAM_BOT_TOKEN) == "None" or str(TELEGRAM_BOT_TOKEN) == "YOUR_TOKEN":
                        writerr(
                            colored(
                                'No value for "TELEGRAM_BOT_TOKEN" in config.yml - default set',
                                "yellow",
                            )
                        )
                        TELEGRAM_BOT_TOKEN = ""
                except Exception:
                    writerr(
                        colored(
                            'Unable to read "TELEGRAM_BOT_TOKEN" from config.yml - default set',
                            "red",
                        )
                    )
                    TELEGRAM_BOT_TOKEN = ""

                try:
                    TELEGRAM_CHAT_ID = config.get("TELEGRAM_CHAT_ID")
                    if str(TELEGRAM_CHAT_ID) == "None" or str(TELEGRAM_CHAT_ID) == "YOUR_CHAT_ID":
                        writerr(
                            colored(
                                'No value for "TELEGRAM_CHAT_ID" in config.yml - default set',
                                "yellow",
                            )
                        )
                        TELEGRAM_CHAT_ID = ""
                except Exception:
                    writerr(
                        colored(
                            'Unable to read "TELEGRAM_CHAT_ID" from config.yml - default set',
                            "red",
                        )
                    )
                    TELEGRAM_CHAT_ID = ""

            try:
                DEFAULT_OUTPUT_DIR = config.get("DEFAULT_OUTPUT_DIR")
                if str(DEFAULT_OUTPUT_DIR) == "None" or str(DEFAULT_OUTPUT_DIR) == "":
                    DEFAULT_OUTPUT_DIR = os.path.expanduser(str(waymorePath))
                else:
                    # Test if DEFAULT_OUTPUT_DIR is a valid directory
                    if not os.path.isdir(DEFAULT_OUTPUT_DIR):
                        writerr(
                            colored(
                                'The "DEFAULT_OUTPUT_DIR" of "'
                                + str(DEFAULT_OUTPUT_DIR)
                                + '" is not a valid directory. Using "'
                                + str(waymorePath)
                                + '" instead.',
                                "yellow",
                            )
                        )
                        DEFAULT_OUTPUT_DIR = os.path.expanduser(str(waymorePath))
                    else:
                        DEFAULT_OUTPUT_DIR = os.path.expanduser(DEFAULT_OUTPUT_DIR)
            except Exception:
                writerr(
                    colored(
                        'Unable to read "DEFAULT_OUTPUT_DIR" from config.yml - default set',
                        "red",
                    )
                )
                DEFAULT_OUTPUT_DIR = waymorePath

        except yaml.YAMLError:  # A scan error occurred reading the file
            useDefaults = True
            if args.config is None:
                writerr(
                    colored(
                        'WARNING: There seems to be a formatting error in "config.yml", so using default values',
                        "yellow",
                    )
                )
            else:
                writerr(
                    colored(
                        'WARNING: There seems to be a formatting error in "'
                        + args.config
                        + '", so using default values',
                        "yellow",
                    )
                )

        except FileNotFoundError:  # The config file wasn't found
            useDefaults = True
            if args.config is None:
                writerr(
                    colored(
                        'WARNING: Cannot find file "config.yml", so using default values',
                        "yellow",
                    )
                )
            else:
                writerr(
                    colored(
                        'WARNING: Cannot find file "' + args.config + '", so using default values',
                        "yellow",
                    )
                )

        except Exception as e:  # Another error occurred
            useDefaults = True
            if args.config is None:
                writerr(
                    colored(
                        'WARNING: Cannot read file "config.yml", so using default values. The following error occurred: '
                        + str(e),
                        "yellow",
                    )
                )
            else:
                writerr(
                    colored(
                        'WARNING: Cannot read file "'
                        + args.config
                        + '", so using default values. The following error occurred: '
                        + str(e),
                        "yellow",
                    )
                )

        # Use defaults if required
        if useDefaults:
            FILTER_URL = DEFAULT_FILTER_URL
            MATCH_MIME = ""
            FILTER_MIME = DEFAULT_FILTER_MIME
            MATCH_CODE = ""
            FILTER_CODE = DEFAULT_FILTER_CODE
            URLSCAN_API_KEY = ""
            VIRUSTOTAL_API_KEY = ""
            INTELX_API_KEY = ""
            FILTER_KEYWORDS = ""
            CONTINUE_RESPONSES_IF_PIPED = True
            WEBHOOK_DISCORD = ""
            TELEGRAM_BOT_TOKEN = ""
            TELEGRAM_CHAT_ID = ""
            DEFAULT_OUTPUT_DIR = os.path.expanduser("~/.config/waymore")
            SOURCE_IP = args.source_ip

        # Build HTTP adapters (after SOURCE_IP is resolved)
        try:
            retry = Retry(
                total=args.retries,
                backoff_factor=1.1,
                status_forcelist=[429, 500, 502, 503, 504],
                raise_on_status=False,
                respect_retry_after_header=False,
            )
            if SOURCE_IP:
                HTTP_ADAPTER = SourceAddressAdapter(source_ip=SOURCE_IP, max_retries=retry)
            else:
                HTTP_ADAPTER = HTTPAdapter(max_retries=retry)
        except Exception as e:
            writerr(colored("ERROR getConfig 2: " + str(e), "red"))

        try:
            retry_cc = Retry(
                total=args.retries + 3,
                backoff_factor=1.1,
                status_forcelist=[503],
                raise_on_status=False,
                respect_retry_after_header=False,
            )
            if SOURCE_IP:
                HTTP_ADAPTER_CC = SourceAddressAdapter(source_ip=SOURCE_IP, max_retries=retry_cc)
            else:
                HTTP_ADAPTER_CC = HTTPAdapter(max_retries=retry_cc)
        except Exception as e:
            writerr(colored("ERROR getConfig 3: " + str(e), "red"))

    except Exception as e:
        writerr(colored("ERROR getConfig 1: " + str(e), "red"))


# Print iterations progress - copied from https://stackoverflow.com/questions/3173320/text-progress-bar-in-terminal-with-block-characters?noredirect=1&lq=1
def printProgressBar(
    iteration,
    total,
    prefix="",
    suffix="",
    decimals=1,
    length=100,
    fill="█",
    printEnd="\r",
):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    # Only show progress bar if not streaming
    if not (args.stream and args.mode == "U"):
        try:
            percent = (
                ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total))).rjust(5)
            )
            filledLength = int(length * iteration // total)
            bar = fill * filledLength + "-" * (length - filledLength)
            # If the program is not piped with something else, write to stdout, otherwise write to stderr
            if sys.stdout.isatty():
                write(colored(f"\r{prefix} |{bar}| {percent}% {suffix}\r", "green"))
            else:
                writerr(colored(f"\r{prefix} |{bar}| {percent}% {suffix}\r", "green"))
            # Print New Line on Complete
            if iteration == total:
                # If the program is not piped with something else, write to stdout, otherwise write to stderr
                if sys.stdout.isatty():
                    write()
                else:
                    writerr()
        except Exception as e:
            if verbose():
                writerr(colored("ERROR printProgressBar: " + str(e), "red"))


def filehash(text):
    """
    Generate a hash value for the passed string or bytes. This is used for the file name of a downloaded archived response
    """
    pass


class WayBackException(Exception):
    """
    A custom exception to raise if archive.org respond with specific text in the response that indicate there is a problem on their side
    """

    def __init__(self):
        message = "WayBackException"
        super().__init__(message)


def fixArchiveOrgUrl(url):
    """
    Sometimes archive.org returns a URL that has %0A at the end followed by other characters. If you try to reach the archive URL with that it will fail, but remove from the %0A (newline) onwards and it succeeds, so it doesn't seem intentionally included. In this case, strip anything from %0A onwards from the URL
    """
    pass


def isLikelyBinaryUrl(url):
    """
    Check if a URL likely points to a binary file based on its extension.
    This is used BEFORE making a request to decide if we need the raw/id_ version.
    """
    pass


def addRawModifier(archiveUrl):
    """
    Add 'id_' modifier to Wayback Machine URL to get raw/original content.
    This is essential for binary files to avoid Wayback modifications.

    Example:
      Input:  https://web.archive.org/web/20090315210455/http://example.com/file.wmv
      Output: https://web.archive.org/web/20090315210455id_/http://example.com/file.wmv
    """
    pass


# Add a link to the linksFound collection for archived responses (included timestamp preifx)
def linksFoundResponseAdd(link):
    global linksFound, argsInput, argsInputHostname, links_lock

    try:
        if inputIsDomainANDPath:
            checkInput = argsInput
        else:
            checkInput = argsInputHostname

        # Remove the timestamp
        linkWithoutTimestamp = link.split("/", 1)[-1]

        # If the link specifies port 80 or 443, e.g. http://example.com:80, then remove the port
        parsed = urlparse(linkWithoutTimestamp.strip())
        if parsed.port in (80, 443):
            new_netloc = parsed.hostname
            parsed_url = parsed._replace(netloc=new_netloc).geturl()
        else:
            parsed_url = linkWithoutTimestamp

        # Don't write it if the link does not contain the requested domain (this can sometimes happen)
        # Use URL decoding to handle %20 spaces and case-insensitive comparison
        if unquote(parsed_url).lower().find(unquote(checkInput).lower()) >= 0:
            with links_lock:
                linksFound.add(link)
            # If streaming is enabled and mode is 'U', print the link to stdout
            if args.stream and args.mode == "U":
                write(link, pipe=True)
    except Exception:
        with links_lock:
            linksFound.add(link)
        # If streaming is enabled and mode is 'U', print the link to stdout
        if args.stream and args.mode == "U":
            write(link, pipe=True)


# Add a link to the linksFound collection
def linksFoundAdd(link, source_set=None):
    global linksFound, argsInput, argsInputHostname, links_lock

    try:
        if inputIsDomainANDPath:
            checkInput = argsInput
        else:
            checkInput = argsInputHostname

        # If the link specifies port 80 or 443, e.g. http://example.com:80, then remove the port
        parsed = urlparse(link.strip())
        if parsed.port in (80, 443):
            new_netloc = parsed.hostname
            parsed_url = parsed._replace(netloc=new_netloc).geturl()
        else:
            parsed_url = link

        # Don't write it if the link does not contain the requested domain (this can sometimes happen)
        # Use URL decoding to handle %20 spaces and case-insensitive comparison
        if unquote(parsed_url).lower().find(unquote(checkInput).lower()) >= 0:
            with links_lock:
                if source_set is not None:
                    source_set.add(link)
                else:
                    linksFound.add(link)
            # If streaming is enabled and mode is 'U', print the link to stdout
            if args.stream and args.mode == "U":
                write(link, pipe=True)
    except Exception:
        with links_lock:
            if source_set is not None:
                source_set.add(link)
            else:
                linksFound.add(link)
        # If streaming is enabled and mode is 'U', print the link to stdout
        if args.stream and args.mode == "U":
            write(link, pipe=True)


def processArchiveUrl(url):
    """
    Get the passed web archive response
    """
    pass


def processURLOutput():
    """
    Show results of the URL output, i.e. getting URLs from archive.org and commoncrawl.org and write results to file
    """
    global linksFound, subs, path, argsInput, checkWayback, checkCommonCrawl, checkAlienVault, checkURLScan, checkVirusTotal, DEFAULT_OUTPUT_DIR, checkIntelx

    try:

        if args.check_only:
            totalRequests = (
                checkWayback
                + checkCommonCrawl
                + checkAlienVault
                + checkURLScan
                + checkVirusTotal
                + checkIntelx
            )
            minutes = totalRequests * 1 // 60
            hours = minutes // 60
            days = hours // 24
            if minutes < 5:
                write(
                    colored(
                        "\n-> Getting URLs (e.g. at 1 req/sec) should be quite quick!",
                        "green",
                    )
                )
            elif hours < 2:
                write(
                    colored(
                        "\n-> Getting URLs (e.g. at 1 req/sec) could take more than "
                        + str(minutes)
                        + " minutes.",
                        "green",
                    )
                )
            elif hours < 6:
                write(
                    colored(
                        "\n-> Getting URLs (e.g. at 1 req/sec) could take more than "
                        + str(hours)
                        + " hours.",
                        "green",
                    )
                )
            elif hours < 24:
                write(
                    colored(
                        "\n-> Getting URLs (e.g. at 1 req/sec) take more than "
                        + str(hours)
                        + " hours.",
                        "yellow",
                    )
                )
            elif days < 7:
                write(
                    colored(
                        "\n-> Getting URLs (e.g. at 1 req/sec) could take more than "
                        + str(days)
                        + " days. Consider using arguments -lr, -ci, -from and -to wisely!",
                        "red",
                    )
                )
            else:
                write(
                    colored(
                        "\n-> Getting URLs (e.g. at 1 req/sec) could take more than "
                        + str(days)
                        + " days!!! Consider using arguments -lr, -ci, -from and -to wisely!",
                        "red",
                    )
                )
            write("")
        elif not (
            args.stream and args.mode == "U" and args.output_urls == ""
        ):  # Only write to file if not streaming OR if streaming but -oU is provided
            linkCount = len(linksFound)
            write(
                getSPACER(
                    colored("\nTotal unique links found for " + subs + argsInput + ": ", "cyan")
                    + colored(str(linkCount) + " 🤘", "white")
                )
                + "\n"
            )

            # If -oU / --output-urls was passed then use that file name, else use "waymore.txt" in the path of the .py file
            if args.output_urls == "":
                # Create 'results' and domain directory if needed
                createDirs()

                # If -oR / --output-responses was passed then set the path to that, otherwise it will be the "results/{target.domain}}" path
                if args.output_responses != "":
                    fullPath = args.output_responses + "/"
                else:
                    fullPath = (
                        str(DEFAULT_OUTPUT_DIR)
                        + "/results/"
                        + str(argsInput).replace("/", "-")
                        + "/"
                    )
                filename = fullPath + "waymore.txt"
                filenameNew = fullPath + "waymore.new"
                filenameOld = fullPath + "waymore.old"
            else:
                filename = args.output_urls
                filenameNew = filename + ".new"
                filenameOld = filename + ".old"
                # If the filename has any "/" in it, remove the contents after the last one to just get the path and create the directories if necessary
                try:
                    if filename.find("/") > 0:
                        f = os.path.basename(filename)
                        p = filename[: -(len(f)) - 1]
                        if p != "" and not os.path.exists(p):
                            os.makedirs(p)
                except Exception as e:
                    if verbose():
                        writerr(colored("ERROR processURLOutput 6: " + str(e), "red"))

            # If the -ow / --output_overwrite argument was passed and the file exists already, get the contents of the file to include
            appendedUrls = False
            if not args.output_overwrite:
                try:
                    with open(filename) as existingLinks:
                        for link in existingLinks.readlines():
                            linksFound.add(link.strip())
                    appendedUrls = True
                except Exception:
                    pass

            # If the -nlf / --new-links-file argument is passed, rename the old links file if it exists
            try:
                if args.new_links_file:
                    if os.path.exists(filename):
                        os.rename(filename, filenameOld)
            except Exception as e:
                if verbose():
                    writerr(colored("ERROR processURLOutput 5: " + str(e), "red"))

            try:
                # Open the output file
                outFile = open(filename, "w")
            except Exception as e:
                if verbose():
                    writerr(colored("ERROR processURLOutput 2: " + str(e), "red"))
                    sys.exit()

            # Go through all links, and output what was found
            # If the -ra --regex-after was passed then only output if it matches
            outputCount = 0
            for link in linksFound:
                try:
                    if args.regex_after is None or re.search(
                        args.regex_after, link, flags=re.IGNORECASE
                    ):
                        outFile.write(link + "\n")
                        # If the tool is piped to pass output to something else, then write the link
                        if not sys.stdout.isatty():
                            write(link, True)
                        outputCount = outputCount + 1
                except Exception as e:
                    if verbose():
                        writerr(colored("ERROR processURLOutput 3: " + str(e), "red"))

            # If there are less links output because of filters, show the new total
            if args.regex_after is not None and linkCount > 0 and outputCount < linkCount:
                write(
                    colored(
                        'Links found after applying filter "' + args.regex_after + '": ',
                        "cyan",
                    )
                    + colored(str(outputCount) + " 🤘\n", "white")
                )

            # Close the output file
            try:
                outFile.close()
            except Exception as e:
                if verbose():
                    writerr(colored("ERROR processURLOutput 4: " + str(e), "red"))

            if verbose():
                if outputCount == 0:
                    write(colored("No links were found so nothing written to file.", "cyan"))
                else:
                    if appendedUrls:
                        write(
                            colored("Links successfully appended to file ", "cyan")
                            + colored(filename, "white")
                            + colored(" and duplicates removed.", "cyan")
                        )
                    else:
                        write(
                            colored("Links successfully written to file ", "cyan")
                            + colored(filename, "white")
                        )

            try:
                # If the -nlf / --new-links-file argument is passes, create the .new file
                if args.new_links_file:

                    # If the file and .old version exists then get the difference to write to .new file
                    if os.path.exists(filenameOld) and os.path.exists(filename):

                        # Get all the old links
                        with open(filenameOld) as oldFile:
                            oldLinks = set(oldFile.readlines())

                        # Get all the new links
                        with open(filename) as newFile:
                            newLinks = set(newFile.readlines())

                        # Create a file with most recent new links
                        with open(filenameNew, "w") as newOnly:
                            for line in list(newLinks - oldLinks):
                                newOnly.write(line)

                        # Delete the old file
                        os.remove(filenameOld)

            except Exception as e:
                if verbose():
                    writerr(colored("ERROR processURLOutput 6: " + str(e), "red"))

    except Exception as e:
        if verbose():
            writerr(colored("ERROR processURLOutput 1: " + str(e), "red"))


def validateArgProcesses(x):
    """
    Validate the -p / --processes argument
    Only allow values between 1 and 5 inclusive
    """
    pass


def stripUnwanted(url):
    """
    Strip the scheme, port number, query string and fragment form any input values if they have them
    """
    parsed = urlparse(url)
    # Strip scheme
    scheme = f"{parsed.scheme}://"
    strippedUrl = parsed.geturl().replace(scheme, "", 1)
    # Strip query string and fragment
    strippedUrl = strippedUrl.split("#")[0].split("?")[0]
    # Strip port number
    if re.search(r"^[^/]*:[0-9]+", strippedUrl):
        strippedUrl = re.sub(r":[0-9]+", "", strippedUrl, 1)
    return strippedUrl


def validateArgInput(x):
    """
    Validate the -i / --input argument.
    Ensure it is a domain only, or a URL, but with no schema or query parameters or fragment
    """
    global inputValues, isInputFile
    # If the input was given through STDIN (piped from another program) then
    if x == "<stdin>":
        stdinFile = sys.stdin.readlines()
        count = 0
        for line in stdinFile:
            # Remove newline characters, and also *. if the domain starts with this
            inputValues.add(stripUnwanted(line.rstrip("\n").lstrip("*.")))
            count = count + 1
        if count > 1:
            isInputFile = True
    else:
        # Determine if a single input was given, or a file
        if os.path.isfile(x):
            isInputFile = True
            # Open file and put all values in input list
            with open(x) as inputFile:
                lines = inputFile.readlines()
            # Check if any lines start with a *. and replace without the *.
            for line in lines:
                inputValues.add(stripUnwanted(line.lstrip("*.")))
        else:
            # Just add the input value to the input list
            inputValues.add(stripUnwanted(x))
    return x


def validateArgStatusCodes(x):
    """
    Validate the -fc and -mc arguments
    Only allow 3 digit numbers separated by a comma
    """
    pass


def validateArgDate(x):
    """
    Validate the -from and -to arguments
    """
    pass


def cdxKeywordsFilter(pattern, filterField="original"):
    """
    Build a filter=original:... string for use in the Wayback CDX API.

    The CDX API filter uses Python re.match() semantics (cf.
    https://docs.python.org/3/library/re.html#re.match).  re.match anchors
    to the START of the string but does NOT require the pattern to match to
    the end.  A .* prefix is therefore always added so the pattern can match
    anywhere in the URL, not just at the very start.

    Whether a trailing .* is added depends on the pattern:
      - If the pattern contains an unescaped $ ($ not preceded by \\),
        no trailing .* is added — $ already asserts end-of-string.
      - Otherwise a trailing .* is appended so that patterns without an
        explicit $ anchor also match URLs where the pattern appears mid-URL.

    The filterField parameter controls the CDX/CommonCrawl filter field:
      - Wayback CDX:    filterField="original"  -> filter=original:.*(...)
      - Common Crawl:   filterField="~url"       -> filter=~url:.*(...)

    Examples:
        r'\\.js'           -> filter=original:.*(\. js).*
        r'\\.js$'          -> filter=original:.*(\. js$)
        r'\\.js(\\?.*|$)' -> filter=original:.*(\. js(\\?.*|$))
        r'\\$'             -> filter=original:.*.(\\$).*  (escaped $, literal)
    """
    has_end_anchor = bool(re.search(r"(?<!\\)\$", pattern))
    suffix = "" if has_end_anchor else ".*"
    return "&filter=" + filterField + ":.*(" + pattern + ")" + suffix


def validateArgMimeTypes(x):
    """
    Validate the -ft and -mt arguments
    The passed values will be changed to lower case.
    Only values matching valid MIME types separated by a comma.
    Allowed characters either side of the single '/': A-Z a-z 0-9 ! # $ % & ' * + - . ^ _ ` { | } ~
    """
    pass


def validateArgProviders(x):
    """
    Validate the --providers argument
    Only the following values in a comma separated list are accepted:
    - wayback
    - commoncrawl
    - otx
    - urlscan
    - virustotal
    - intelx
    - ghostarchive
    """
    pass


def validateArgIPAddress(x):
    """
    Validate the --source-ip argument
    Accepts IPv4 or IPv6 addresses.
    """
    pass


def parseDateArg(dateArg):
    """
    Parse a date argument from the command line into a datetime object
    """
    pass


def processAlienVaultPage(url):
    """
    Get URLs from a specific page of otx.alienvault.org API for the input domain
    """
    pass


def getAlienVaultUrls():
    """
    Get URLs from the Alien Vault OTX, otx.alienvault.com
    """
    pass


def processURLScanUrl(url, httpCode, mimeType, urlscanID=""):
    """
    Process a specific URL from urlscan.io to determine whether to save the link
    """
    global argsInput, argsInputHostname, urlscanRequestLinks, links_lock, linkCountURLScan, linksFoundURLScan

    addLink = True

    try:
        # If the input has a / in it, then a URL was passed, so the link will only be added if the URL matches
        if "/" in url:
            if argsInput not in url:
                addLink = False

        # If filters are required then test them
        if addLink and not args.filter_responses_only:

            # If the user requested -n / --no-subs then we don't want to add it if it has a sub domain (www. will not be classed as a sub domain)
            if args.no_subs:
                match = re.search(
                    r"^[A-za-z]*\:\/\/(www\.)?" + re.escape(argsInputHostname),
                    url,
                    flags=re.IGNORECASE,
                )
                if match is None:
                    addLink = False

            # If the user didn't requested -f / --filter-responses-only then check http code
            if addLink and not args.filter_responses_only:

                # Compare the HTTP code against the Code exclusions and matches
                if MATCH_CODE != "":
                    match = re.search(
                        r"(" + re.escape(MATCH_CODE).replace(",", "|") + ")",
                        httpCode,
                        flags=re.IGNORECASE,
                    )
                    if match is None:
                        addLink = False
                else:
                    match = re.search(
                        r"(" + re.escape(FILTER_CODE).replace(",", "|") + ")",
                        httpCode,
                        flags=re.IGNORECASE,
                    )
                    if match is not None:
                        addLink = False

                # Check the URL exclusions
                if addLink:
                    match = re.search(
                        r"(" + re.escape(FILTER_URL).replace(",", "|") + ")",
                        url,
                        flags=re.IGNORECASE,
                    )
                    if match is not None:
                        addLink = False

                # Set keywords filter if -ko argument passed
                if addLink and args.keywords_only:
                    if args.keywords_only == "#CONFIG":
                        match = re.search(
                            r"(" + re.escape(FILTER_KEYWORDS).replace(",", "|") + ")",
                            url,
                            flags=re.IGNORECASE,
                        )
                    else:
                        match = re.search(r"(" + args.keywords_only + ")", url, flags=re.IGNORECASE)
                    if match is None:
                        addLink = False

                # Check the MIME exclusions
                if mimeType != "":
                    if MATCH_MIME != "":
                        match = re.search(
                            r"(" + re.escape(MATCH_MIME).replace(",", "|") + ")",
                            mimeType,
                            flags=re.IGNORECASE,
                        )
                        if match is None:
                            addLink = False
                    else:
                        match = re.search(
                            r"(" + re.escape(FILTER_MIME).replace(",", "|") + ")",
                            mimeType,
                            flags=re.IGNORECASE,
                        )
                        if match is not None:
                            addLink = False

                # Add MIME Types if --verbose option was selected
                if verbose():
                    if mimeType.strip() != "":
                        with links_lock:
                            if linkMimes is not None:
                                linkMimes.add(mimeType)

        # Add link if it passed filters
        if addLink:
            # Just get the hostname of the url
            tldExtract = tldextract.extract(url)
            subDomain = tldExtract.subdomain
            if subDomain != "":
                subDomain = subDomain + "."
            domainOnly = subDomain + tldExtract.domain + "." + tldExtract.suffix

            # URLScan might return URLs that aren't for the domain passed so we need to check for those and not process them
            # Check the URL
            match = re.search(
                r"(^|\.)" + re.escape(argsInputHostname) + "$",
                domainOnly,
                flags=re.IGNORECASE,
            )
            if match is not None:
                if args.mode in ("U", "B"):
                    # Ensure linksFoundURLScan is initialized (can be None during concurrent execution)
                    if linksFoundURLScan is None:
                        linksFoundURLScan = set()
                    linksFoundAdd(url, linksFoundURLScan)
                # If Response mode is requested then add the DOM ID to try later, for the number of responses wanted
                if urlscanID != "" and args.mode in ("R", "B"):
                    if args.limit == 0 or len(urlscanRequestLinks) < args.limit:
                        with links_lock:
                            urlscanRequestLinks.add((url, URLSCAN_DOM_URL + urlscanID))

    except Exception as e:
        writerr(colored("ERROR processURLScanUrl 1: " + str(e), "red"))


def getURLScanDOM(originalUrl, domUrl):
    """
    Get the DOM for the passed URLScan link
    """
    pass


def getGhostArchiveWARC(originalUrl, domUrl):
    """
    Get the DOM for the passed GhostArchive link - parses WARC files containing multiple request/response pairs
    """
    pass


def format_date_for_urlscan(date_str):
    # Handle different lengths of input
    if len(date_str) == 4:  # YYYY
        date_str += "0101"
    elif len(date_str) == 6:  # YYYYMM
        date_str += "01"

    # Convert to YYYY-MM-DD format
    try:
        formatted_date = datetime.strptime(date_str, "%Y%m%d").strftime("%Y-%m-%d")
        return formatted_date
    except Exception:
        return ""


def getURLScanUrls():
    """
    Get URLs from the URLSCan API, urlscan.io
    """
    global URLSCAN_API_KEY, linksFound, linkMimes, waymorePath, subs, stopProgram, stopSourceURLScan, argsInput, checkURLScan, argsInputHostname, linkCountURLScan, linksFoundURLScan

    # Write the file of URL's for the passed domain/URL
    try:
        requestsMade = 0
        stopSourceURLScan = False
        linksFoundURLScan = set()
        totalUrls = 0
        checkResponse = True

        # Set the URL to just the hostname
        url = URLSCAN_URL.replace("{DOMAIN}", quote(argsInputHostname))

        # If the --from-date or --to-date parameters were paassed then also add a date filter
        if args.from_date or args.to_date:
            if args.from_date:
                fromDate = format_date_for_urlscan(str(args.from_date)[:8])
            else:
                fromDate = "2016-01-01"  # The year URLScan started
            if args.to_date:
                toDate = format_date_for_urlscan(str(args.to_date)[:8])
            else:
                toDate = "now"
            url = url.replace("{DATERANGE}", f"%20date:[{fromDate}%20TO%20{toDate}]")
        else:
            url = url.replace("{DATERANGE}", "")

        if verbose():
            if args.mode == "R":
                write(
                    colored(
                        "URLScan - [ INFO ] The URLScan URL requested to get links for responses: ",
                        "magenta",
                    )
                    + colored(url + "\n", "white")
                )
            else:
                write(
                    colored(
                        "URLScan - [ INFO ] The URLScan URL requested to get links: ", "magenta"
                    )
                    + colored(url + "\n", "white")
                )

        if args.mode in ("U", "B") and not args.check_only:
            write(
                colored(
                    "URLScan - [ INFO ] Getting links from urlscan.io API (this can take a while for some domains)...",
                    "cyan",
                )
            )

        # Get the first page from urlscan.io
        try:
            # Choose a random user agent string to use for any requests
            # For other sources we would use `random.choice(USER_AGENT)` to asignn a random user-agent, but it seems
            # that there are a handful of those that ALWAYS return 429. Passing a specific one all the time seems to
            # be successful all the time
            userAgent = "waymore v" + __version__ + " by xnl-h4ck3r"
            session = requests.Session()
            session.mount("https://", HTTP_ADAPTER)
            session.mount("http://", HTTP_ADAPTER)
            # Pass the API-Key header too. This can change the max endpoints per page, depending on URLScan subscription
            resp = session.get(url, headers={"User-Agent": userAgent, "API-Key": URLSCAN_API_KEY})
            requestsMade = requestsMade + 1
        except Exception as e:
            write(
                colored(
                    "URLScan - [ ERR ] Unable to get links from urlscan.io: " + str(e),
                    "red",
                )
            )
            return

        # If the rate limit was reached then determine if to wait and then try again
        if resp.status_code == 429:
            # Get the number of seconds the rate limit resets
            match = re.search(r"Reset in (\d+) seconds", resp.text, flags=re.IGNORECASE)
            if match is not None:
                seconds = int(match.group(1))
                if seconds <= args.urlscan_rate_limit_retry * 60:
                    writerr(
                        colored(
                            "URLScan - [ 429 ] Rate limit reached, so waiting for another "
                            + str(seconds)
                            + " seconds before continuing...",
                            "yellow",
                        )
                    )
                    # Wait can be interrupted by SIGINT via interrupt_event
                    interrupt_event.clear()
                    if interrupt_event.wait(seconds + 1):
                        # Interrupted by SIGINT
                        return
                    try:
                        resp = session.get(
                            url,
                            headers={
                                "User-Agent": userAgent,
                                "API-Key": URLSCAN_API_KEY,
                            },
                        )
                        requestsMade = requestsMade + 1
                    except Exception as e:
                        write(
                            colored(
                                "URLScan - [ ERR ] Unable to get links from urlscan.io: " + str(e),
                                "red",
                            )
                        )
                        return

        # If the rate limit was reached or if a 401 (which likely means the API key isn't valid), try without API key
        if resp.status_code in (401, 429):
            if URLSCAN_API_KEY != "":
                try:
                    if resp.status_code == 429:
                        writerr(
                            colored(
                                "URLScan - [ 429 ] Rate limit reached so trying without API Key...",
                                "red",
                            )
                        )
                    else:
                        writerr(
                            colored(
                                "URLScan - [ INF ] The API Key is invalid so trying without API Key...",
                                "red",
                            )
                        )
                    # Set key to blank for further requests
                    URLSCAN_API_KEY = ""
                    session_no_key = requests.Session()
                    session_no_key.mount("https://", HTTP_ADAPTER)
                    session_no_key.mount("http://", HTTP_ADAPTER)
                    resp = session_no_key.get(url, headers={"User-Agent": userAgent})
                except Exception as e:
                    writerr(
                        colored(
                            "URLScan - [ ERR ] Unable to get links from urlscan.io: " + str(e),
                            "red",
                        )
                    )
                    checkResponse = False

                # If the rate limit was reached end now
                if resp.status_code == 429:
                    writerr(
                        colored(
                            "URLScan - [ 429 ] Rate limit reached without API Key so unable to get links.",
                            "red",
                        )
                    )
                    checkResponse = False
            else:
                writerr(
                    colored(
                        "URLScan - [ 429 ] Rate limit reached so unable to get links.",
                        "red",
                    )
                )
                checkResponse = False
        elif resp.status_code != 200:
            writerr(
                colored(
                    "URLScan - [ "
                    + str(resp.status_code)
                    + " ] Unable to get links from urlscan.io",
                    "red",
                )
            )
            checkResponse = False

        try:
            if checkResponse:
                # Get the JSON response
                jsonResp = json.loads(resp.text.strip())

                # Get the number of results
                totalUrls = int(jsonResp["total"])
        except Exception:
            writerr(
                colored(
                    "URLScan - [ ERR ] There was an unexpected response from the API",
                    "red",
                )
            )

        # Carry on if something was found
        if args.check_only and args.mode != "R":
            try:
                hasMore = jsonResp["has_more"]
                if hasMore:
                    write(
                        colored("URLScan - [ INFO ] Get URLs from URLScan: ", "cyan")
                        + colored("UNKNOWN requests", "white")
                    )
                else:
                    write(
                        colored("URLScan - [ INFO ] Get URLs from URLScan: ", "cyan")
                        + colored("1 request", "white")
                    )
            except Exception:
                pass
            checkURLScan = 1

        else:
            # Carry on if something was found
            if int(totalUrls) > 0:

                while not stopSourceURLScan:

                    searchAfter = ""

                    # Get memory in case it exceeds threshold
                    getMemory()

                    # Go through each URL in the list
                    for urlSection in jsonResp["results"]:

                        # Get the URL
                        try:
                            foundUrl = urlSection["page"]["url"]
                        except Exception:
                            foundUrl = ""

                        # Also get the "ptr" field which can also be a url we want
                        try:
                            pointer = urlSection["page"]["ptr"]
                            if not pointer.startswith("http"):
                                pointer = "http://" + pointer
                        except Exception:
                            pointer = ""

                        # Also get the "task" url field
                        try:
                            taskUrl = urlSection["task"]["url"]
                            if not taskUrl.startswith("http"):
                                taskUrl = "http://" + taskUrl
                        except Exception:
                            taskUrl = ""

                        # Get the sort value used for the search_after parameter to get to the next page later
                        try:
                            sort = urlSection["sort"]
                        except Exception:
                            sort = ""
                        searchAfter = "&search_after=" + str(sort[0]) + "," + str(sort[1])

                        # Get the HTTP code
                        try:
                            httpCode = str(urlSection["page"]["status"])
                        except Exception:
                            httpCode = "UNKNOWN"

                        # Get the MIME type
                        try:
                            mimeType = urlSection["page"]["mimeType"]
                        except Exception:
                            mimeType = ""

                        # If we are going to be downloading responses, then get the unique ID to retrieve the DOM later
                        urlscanID = ""
                        if args.mode in ("R", "B"):
                            try:
                                urlscanID = urlSection["_id"]
                            except Exception:
                                pass

                        # If a URL was found the process it
                        if foundUrl != "":
                            processURLScanUrl(foundUrl, httpCode, mimeType, urlscanID)

                        # If a pointer was found the process it
                        if pointer != "":
                            processURLScanUrl(pointer, httpCode, mimeType)

                        # If a task url was found the process it
                        if taskUrl != "":
                            processURLScanUrl(taskUrl, httpCode, mimeType)

                    # If we have the field value to go to the next page...
                    if searchAfter != "":

                        keepTrying = True
                        while not stopSourceURLScan and keepTrying:
                            keepTrying = False
                            # Get the next page from urlscan.io
                            try:
                                # Choose a random user agent string to use for any requests
                                session = requests.Session()
                                session.mount("https://", HTTP_ADAPTER)
                                session.mount("http://", HTTP_ADAPTER)
                                # Pass the API-Key header too. This can change the max endpoints per page, depending on URLScan subscription
                                resp = session.get(
                                    url + searchAfter,
                                    headers={
                                        "User-Agent": userAgent,
                                        "API-Key": URLSCAN_API_KEY,
                                    },
                                )
                                requestsMade = requestsMade + 1
                            except Exception as e:
                                writerr(
                                    colored(
                                        "URLScan - [ ERR ] Unable to get links from urlscan.io: "
                                        + str(e),
                                        "red",
                                    )
                                )
                                pass

                            # If the rate limit was reached
                            if resp.status_code == 429:
                                # Get the number of seconds the rate limit resets
                                match = re.search(
                                    r"Reset in (\d+) seconds",
                                    resp.text,
                                    flags=re.IGNORECASE,
                                )
                                if match is not None:
                                    seconds = int(match.group(1))
                                    if seconds <= args.urlscan_rate_limit_retry * 60:
                                        writerr(
                                            colored(
                                                "URLScan - [ 429 ] Rate limit reached, so waiting for another "
                                                + str(seconds)
                                                + " seconds before continuing...",
                                                "yellow",
                                            )
                                        )
                                        # Wait can be interrupted by SIGINT via interrupt_event
                                        interrupt_event.clear()
                                        if interrupt_event.wait(seconds + 1):
                                            # Interrupted by SIGINT
                                            keepTrying = False
                                            break
                                        keepTrying = True
                                        continue
                                    else:
                                        writerr(
                                            colored(
                                                "URLScan - [ 429 ] Rate limit reached (waiting time of "
                                                + str(seconds)
                                                + "), so stopping. Links that have already been retrieved will be saved.",
                                                "red",
                                            )
                                        )
                                        stopSourceURLScan = True
                                        pass
                                else:
                                    writerr(
                                        colored(
                                            "URLScan - [ 429 ] Rate limit reached, so stopping. Links that have already been retrieved will be saved.",
                                            "red",
                                        )
                                    )
                                    stopSourceURLScan = True
                                    pass
                            elif resp.status_code != 200:
                                writerr(
                                    colored(
                                        "URLScan - [ "
                                        + str(resp.status_code)
                                        + " ] Unable to get links from urlscan.io",
                                        "red",
                                    )
                                )
                                stopSourceURLScan = True
                                pass

                        if not stopSourceURLScan:
                            # Get the JSON response
                            jsonResp = json.loads(resp.text.strip())

                            # If there are no more results, or if the requests limit was specified and has been exceeded, then stop
                            if (
                                jsonResp["results"] is None
                                or len(jsonResp["results"]) == 0
                                or (args.limit_requests != 0 and requestsMade > args.limit_requests)
                                or (
                                    args.mode == "R"
                                    and args.limit != 0
                                    and requestsMade > args.limit
                                )
                            ):
                                stopSourceURLScan = True

            # Show the MIME types found (in case user wants to exclude more)
            if verbose() and linkMimes is not None and len(linkMimes) > 0 and args.mode != "R":
                linkMimes.discard("warc/revisit")
                write(
                    colored("URLScan - [ INFO ] MIME types found: ", "magenta")
                    + colored(str(linkMimes), "white")
                    + "\n"
                )

            if args.mode != "R":
                if linksFoundURLScan is not None:
                    linkCountURLScan = len(linksFoundURLScan)
                    write(
                        colored("URLScan - [ INFO ] Links found on urlscan.io: ", "cyan")
                        + colored(str(linkCountURLScan), "white")
                    )
                    if linksFound is not None:
                        linksFound.update(linksFoundURLScan)
                    linksFoundURLScan.clear()
                else:
                    linkCountURLScan = 0
                    write(
                        colored("URLScan - [ INFO ] Links found on urlscan.io: ", "cyan")
                        + colored("0", "white")
                    )

    except Exception as e:
        writerr(colored("ERROR getURLScanUrls 1: " + str(e), "red"))


def processWayBackPage(url):
    """
    Get URLs from a specific page of archive.org CDX API for the input domain
    """
    pass


def getWaybackUrls():
    """
    Get URLs from the Wayback Machine, archive.org
    """
    pass


def processCommonCrawlCollection(cdxApiUrl):
    """
    Get URLs from a given Common Crawl index collection
    """
    pass


def getCommonCrawlIndexes():
    """
    Requests the Common Crawl index file "collinfo.json" if it is not cached locally, or if the local file is older than a month.
    """
    pass


def getCommonCrawlUrls():
    """
    Get all Common Crawl index collections to get all URLs from each one
    """
    pass


def processVirusTotalUrl(url):
    """
    Process a specific URL from virustotal.com to determine whether to save the link
    """
    pass


def getVirusTotalUrls():
    """
    Get URLs from the VirusTotal API v2 and process them.
    Each URL is normalized as (url, scan_date) tuple. Dates are filtered according to args.from_date / args.to_date.
    """
    pass


def processIntelxUrl(url):
    """
    Process a specific URL from intelx.io to determine whether to save the link
    """
    pass


def processIntelxType(target, credits):
    """
    target: 1 - Domains
    target: 3 - URLs
    """
    pass


def getIntelxAccountInfo() -> str:
    """
    Get the account info and return the number of Credits remaining from the /phonebook/search
    """
    pass


def getIntelxUrls():
    """
    Get URLs from the Intelligence X Phonebook search
    """
    pass


def processGhostArchiveUrl(url, ghostArchiveID=""):
    """
    Process a specific URL from ghostarchive.org to determine whether to save the link
    """
    global argsInput, argsInputHostname, links_lock, linkCountGhostArchive, linksFoundGhostArchive

    addLink = True

    try:
        # Strip Wayback Machine prefix if present (e.g., https://web.archive.org/web/20230101120000_/https://example.com)
        waybackMatch = re.match(r"^https?://web\.archive\.org/[^/]+/[a-zA-Z0-9]+_/", url)
        if waybackMatch:
            url = url[waybackMatch.end() :]

        # If the input has a / in it, then a URL was passed, so the link will only be added if the URL matches
        if "/" in url:
            if argsInput not in url:
                addLink = False

        # If filters are required then test them
        if addLink and not args.filter_responses_only:

            # If the user requested -n / --no-subs then we don't want to add it if it has a sub domain (www. will not be classed as a sub domain)
            if args.no_subs:
                match = re.search(
                    r"^[A-za-z]*\:\/\/(www\.)?" + re.escape(argsInputHostname),
                    url,
                    flags=re.IGNORECASE,
                )
                if match is None:
                    addLink = False

            # If the user didn't requested -f / --filter-responses-only then check http code
            if addLink and not args.filter_responses_only:

                # Check the URL exclusions
                if addLink:
                    match = re.search(
                        r"(" + re.escape(FILTER_URL).replace(",", "|") + ")",
                        url,
                        flags=re.IGNORECASE,
                    )
                    if match is not None:
                        addLink = False

                # Set keywords filter if -ko argument passed
                if addLink and args.keywords_only:
                    if args.keywords_only == "#CONFIG":
                        match = re.search(
                            r"(" + re.escape(FILTER_KEYWORDS).replace(",", "|") + ")",
                            url,
                            flags=re.IGNORECASE,
                        )
                    else:
                        match = re.search(r"(" + args.keywords_only + ")", url, flags=re.IGNORECASE)
                    if match is None:
                        addLink = False

        # Add link if it passed filters
        if addLink:
            # Just get the hostname of the url
            tldExtract = tldextract.extract(url)
            subDomain = tldExtract.subdomain
            if subDomain != "":
                subDomain = subDomain + "."
            domainOnly = subDomain + tldExtract.domain + "." + tldExtract.suffix

            # GhostArchive might return URLs that aren't for the domain passed so we need to check for those and not process them
            # Check the URL
            match = re.search(
                r"(^|\.)" + re.escape(argsInputHostname) + "$",
                domainOnly,
                flags=re.IGNORECASE,
            )
            if match is not None:
                if args.mode in ("U", "B"):
                    linksFoundAdd(url, linksFoundGhostArchive)
                # If Response mode is requested then add the DOM ID to try later, for the number of responses wanted
                if ghostArchiveID != "" and args.mode in ("R", "B"):
                    if args.limit == 0 or len(ghostArchiveRequestLinks) < args.limit:
                        with links_lock:
                            ghostArchiveRequestLinks.add(
                                (url, GHOSTARCHIVE_DOM_URL + ghostArchiveID)
                            )

    except Exception as e:
        writerr(colored("ERROR processGhostArchiveUrl 1: " + str(e), "red"))


def getGhostArchiveUrls():
    """
    Get URLs from GhostArchive (ghostarchive.org)
    This source doesn't have an API, so we crawl the HTML pages directly.
    """
    global linksFound, path, subs, stopProgram, stopSourceGhostArchive, argsInput, checkGhostArchive, argsInputHostname, linkCountGhostArchive, linksFoundGhostArchive

    try:
        stopSourceGhostArchive = False
        linksFoundGhostArchive = set()

        # Build the base URL
        # If there is only one . in the hostname, we can guarantee that a subdoman wasn't passed, so we can prefix with . to the links quicker as it won't include other domains that end with the target domain,
        # Else, we need to get all and then confirm the actual host of the links later
        if argsInputHostname.count(".") == 1:
            baseUrl = GHOSTARCHIVE_URL.replace("{DOMAIN}", "." + quote(argsInput))
        else:
            baseUrl = GHOSTARCHIVE_URL.replace("{DOMAIN}", quote(argsInput))

        if verbose():
            write(
                colored("GhostArchive - [ INFO ] The URL requested to get links: ", "magenta")
                + colored(baseUrl + "0\n", "white")
            )

        if not args.check_only and args.mode == "U":
            write(
                colored(
                    "GhostArchive - [ INFO ] Getting links from ghostarchive.org (this can take a while for some domains)...",
                    "cyan",
                )
            )

        # Set up session with cookie
        session = requests.Session()
        if HTTP_ADAPTER is not None:
            session.mount("https://", HTTP_ADAPTER)
            session.mount("http://", HTTP_ADAPTER)

        userAgent = random.choice(USER_AGENT)
        headers = {"User-Agent": userAgent}
        cookies = {"theme": "original"}

        pageNum = 0

        while stopProgram is None and not stopSourceGhostArchive:
            getMemory()

            url = baseUrl + str(pageNum)

            try:
                resp = session.get(url, headers=headers, cookies=cookies, timeout=DEFAULT_TIMEOUT)
            except Exception as e:
                writerr(
                    colored(
                        "GhostArchive - [ ERR ] Unable to get page " + str(pageNum) + ": " + str(e),
                        "red",
                    )
                )
                break

            if resp.status_code == 429:
                writerr(
                    colored(
                        "GhostArchive - [ 429 ] Rate limit reached at page " + str(pageNum) + ".",
                        "red",
                    )
                )
                break

            # Check for maintenance/end of results indicator
            if (
                resp.status_code == 503
                or "The site is under maintenance and will be back soon" in resp.text
                or "No archives for that site" in resp.text
            ):
                if verbose():
                    if pageNum == 0:
                        if args.check_only:
                            checkGhostArchive = 1
                            write(
                                colored(
                                    "GhostArchive - [ INFO ] Get URLs from GhostArchive: ", "cyan"
                                )
                                + colored("1 request", "white")
                            )
                        else:
                            write(
                                colored(
                                    "GhostArchive - [ INFO ] No results found",
                                    "cyan",
                                )
                            )
                    else:
                        write(
                            colored(
                                "GhostArchive - [ INFO ] Retrieved all results from "
                                + str(pageNum)
                                + " pages",
                                "cyan",
                            )
                        )
                break
            if resp.status_code != 200:
                writerr(
                    colored(
                        "GhostArchive - [ ERR ] [ "
                        + str(resp.status_code)
                        + " ] at page "
                        + str(pageNum),
                        "red",
                    )
                )
                break

            # Check only mode - just count pages
            if args.check_only:
                # For check only, we check if there are results and try to get total count
                if pageNum == 0:
                    # Check if there are any results on the first page
                    if '<a href="/archive/' in resp.text:
                        # Try to find "out of X" to determine total results/pages
                        outOfMatch = re.search(r"out of (\d+)", resp.text)
                        if outOfMatch:
                            totalResults = int(outOfMatch.group(1))
                            checkGhostArchive = totalResults
                            write(
                                colored(
                                    "GhostArchive - [ INFO ] Get URLs from GhostArchive: ", "cyan"
                                )
                                + colored(f"{totalResults} requests (pagination required)", "white")
                            )
                        else:
                            checkGhostArchive = 1
                            write(
                                colored(
                                    "GhostArchive - [ INFO ] Get URLs from GhostArchive: ", "cyan"
                                )
                                + colored("unknown requests (pagination required)", "white")
                            )
                    else:
                        checkGhostArchive = 1
                        write(
                            colored("GhostArchive - [ INFO ] Get URLs from GhostArchive: ", "cyan")
                            + colored("1 request (no results)", "white")
                        )
                break

            # Use regex to extract URLs from anchor tag text content
            # Pattern matches: <a href="/archive/ID">URL_HERE</a> - captures both href path and URL
            pattern = r'<a href="(/archive/[^"]*)">([^<]+)</a>'
            matches = re.findall(pattern, resp.text)

            # If no matches found, we've reached the end of results
            if not matches:
                if verbose():
                    write(
                        colored(
                            "GhostArchive - [ INFO ] Retrieved all results from "
                            + str(pageNum + 1)
                            + " pages",
                            "cyan",
                        )
                    )
                break

            for match in matches:
                ghostArchiveId = match[0]  # e.g., "/archive/gkOOR"
                potentialUrl = match[1].strip()
                processGhostArchiveUrl(potentialUrl, ghostArchiveId)

            # Check if there's a "Next Page" link - if not, we've reached the last page
            # GhostArchive resets to Page 1 when exceeding actual pages, so checking for Next Page is essential
            if "Next Page" not in resp.text and ">»</a>" not in resp.text:
                if verbose():
                    write(
                        colored(
                            "GhostArchive - [ INFO ] Retrieved all results from "
                            + str(pageNum + 1)
                            + " pages",
                            "cyan",
                        )
                    )
                break

            pageNum += 1

        if not args.check_only:
            # Count links based on mode - in R mode, count response links; in U/B mode, count URL links
            if args.mode == "R":
                if ghostArchiveRequestLinks is not None:
                    linkCountGhostArchive = len(ghostArchiveRequestLinks)
                else:
                    linkCountGhostArchive = 0
            else:
                if linksFoundGhostArchive is not None:
                    linkCountGhostArchive = len(linksFoundGhostArchive)
                else:
                    linkCountGhostArchive = 0
            write(
                colored("GhostArchive - [ INFO ] Links found on ghostarchive.org: ", "cyan")
                + colored(str(linkCountGhostArchive), "white")
            )
            if linksFoundGhostArchive is not None:
                if linksFound is not None:
                    linksFound.update(linksFoundGhostArchive)
                linksFoundGhostArchive.clear()

    except Exception as e:
        writerr(colored("ERROR getGhostArchiveUrls 1: " + str(e), "red"))


def processResponses():
    """
    Get archived responses from al sources
    """
    global stopProgram, totalFileCount
    try:

        # Get responses from GhostArchive unless excluded
        if stopProgram is None and not args.xga:
            processResponsesGhostArchive()

        # Get responses from URLScan unless excluded
        if stopProgram is None and not args.xus:
            processResponsesURLScan()

        # Get responses from wayback machine unless excluded
        if stopProgram is None and not args.xwm:
            processResponsesWayback()

        # If requested, generate the combined inline JS files
        if (
            not args.check_only
            and stopProgram is None
            and totalFileCount > 0
            and args.output_inline_js
        ):
            combineInlineJS()

    except Exception as e:
        writerr(colored(getSPACER("ERROR processResponses 1: " + str(e)), "red"))


def processResponsesGhostArchive():
    """
    Get archived responses from GhostArchive (ghostarchive.org)
    """
    global subs, path, indexFile, totalResponses, stopProgram, argsInput, successCount, fileCount, DEFAULT_OUTPUT_DIR, responseOutputDirectory, ghostArchiveRequestLinks, failureCount, totalFileCount, checkGhostArchive
    try:
        fileCount = 0
        failureCount = 0
        if not args.check_only:
            # Create 'results' and domain directory if needed
            createDirs()

            # Get the path of the files, depending on whether -oR / --output_responses was passed
            try:
                responsesPath = responseOutputDirectory + "responses.GhostArchive.tmp"
                indexPath = responseOutputDirectory + "waymore_index.txt"
            except Exception as e:
                if verbose():
                    writerr(colored("ERROR processResponsesGhostArchive 4: " + str(e), "red"))

        # Get URLs from GhostArchive if the DOM ID's haven't been retrieved yet
        if stopProgram is None and not args.check_only:
            if args.mode in ("R", "B"):
                write(
                    colored(
                        "GhostArchive - [ INFO ] Getting list of response links (this can take a while for some domains)...",
                        "cyan",
                    )
                )
            if args.mode == "R":
                getGhostArchiveUrls()

        # Check if a responses.GhostArchive.tmp files exists
        if not args.check_only and os.path.exists(responsesPath):

            # Load the links into the set
            with open(responsesPath, "rb") as fl:
                linkRequests = pickle.load(fl)

        # Set start point
        successCount = 0

        # Get the URLScan DOM links
        linkRequests = []
        for originalUrl, domUrl in ghostArchiveRequestLinks:
            linkRequests.append((originalUrl, domUrl))

        # Write the links to a temp file
        if not args.check_only:
            with open(responsesPath, "wb") as f:
                pickle.dump(linkRequests, f)

        # Get the total number of responses we will try to get and set the current file count to the success count
        totalResponses = len(linkRequests)
        checkGhostArchive = checkGhostArchive + totalResponses

        # If there are no reponses to download, diaplay an error and exit
        if args.mode != "R" and totalResponses == 0:
            writerr(
                colored(
                    getSPACER(
                        "Failed to get responses from GhostArchive (ghostarchive.org) - check input and try again."
                    ),
                    "red",
                )
            )
            return

        fileCount = successCount

        if args.check_only:
            writerr(
                colored("Downloading archived responses: ", "cyan")
                + colored("UNKNOWN requests", "cyan")
            )
            writerr(
                colored(
                    "\n-> Downloading the responses can vary depending on the target and the rate limiting on GhostArchive",
                    "green",
                )
            )
            write("")
        else:
            # If the limit has been set over the default, give a warning that this could take a long time!
            if totalResponses - successCount > DEFAULT_LIMIT:
                if successCount > 0:
                    writerr(
                        colored(
                            getSPACER(
                                "WARNING: Downloading remaining "
                                + str(totalResponses - successCount)
                                + " responses may take a loooooooong time! Consider using arguments -ko, -l, -ci, -from and -to wisely!"
                            ),
                            "yellow",
                        )
                    )
                else:
                    writerr(
                        colored(
                            getSPACER(
                                "WARNING: Downloading "
                                + str(totalResponses)
                                + " responses may take a loooooooong time! Consider using arguments -ko, -l, -ci, -from and -to wisely!"
                            ),
                            "yellow",
                        )
                    )

            # Open the index file if hash value is going to be used (not URL)
            if not args.url_filename:
                indexFile = open(indexPath, "a")

            # Process the URLs from GhostArchive
            if stopProgram is None:
                p = mp.Pool(
                    args.processes * 2
                )  # Double the number of processes to speed up the download
                p.starmap(getGhostArchiveWARC, linkRequests[successCount:])
                p.close()
                p.join()

            # Delete the tmp files now it has run successfully
            if stopProgram is None:
                try:
                    os.remove(responsesPath)
                except Exception:
                    pass

            # Close the index file if hash value is going to be used (not URL)
            if not args.url_filename:
                indexFile.close()

        if not args.check_only:
            try:
                if failureCount > 0:
                    if verbose():
                        write(
                            colored("GhostArchive - [ INFO ] Responses saved to ", "cyan")
                            + colored(responseOutputDirectory, "white")
                            + colored(" for " + subs + argsInput + ": ", "cyan")
                            + colored(
                                str(fileCount) + " 🤘",
                                "white",
                            )
                            + colored(" (" + str(failureCount) + " not found)\n", "red")
                        )
                    else:
                        write(
                            colored("GhostArchive - [ INFO ] Responses saved to ", "cyan")
                            + colored(responseOutputDirectory, "white")
                            + colored(" for " + subs + argsInput + ": ", "cyan")
                            + colored(str(fileCount) + " 🤘", "white")
                            + colored(" (" + str(failureCount) + " not found)\n", "red")
                        )
                else:
                    if verbose():
                        write(
                            colored("GhostArchive - [ INFO ] Responses saved to ", "cyan")
                            + colored(responseOutputDirectory, "white")
                            + colored(" for " + subs + argsInput + ": ", "cyan")
                            + colored(str(fileCount) + " 🤘\n", "white")
                        )
                    else:
                        write(
                            colored("GhostArchive - [ INFO ] Responses saved to ", "cyan")
                            + colored(responseOutputDirectory, "white")
                            + colored(" for " + subs + argsInput + ": ", "cyan")
                            + colored(str(fileCount) + " 🤘\n", "white")
                        )
            except Exception as e:
                if verbose():
                    writerr(colored("ERROR processResponsesGhostArchive 5: " + str(e), "red"))

            # Append extra links from WARC files to URL output file (for mode B)
            try:
                if args.mode == "B" and len(extraWarcLinks) > 0:
                    # Determine URL output file path (same logic as processURLOutput)
                    if args.output_urls == "":
                        if args.output_responses != "":
                            urlFilePath = args.output_responses + "/waymore.txt"
                        else:
                            urlFilePath = (
                                str(DEFAULT_OUTPUT_DIR)
                                + "/results/"
                                + str(argsInput).replace("/", "-")
                                + "/waymore.txt"
                            )
                    else:
                        urlFilePath = args.output_urls

                    # Load existing URLs from file to avoid duplicates
                    existingUrls = set()
                    try:
                        with open(urlFilePath) as f:
                            for line in f:
                                existingUrls.add(line.strip())
                    except Exception:
                        pass

                    # Append only new unique URLs
                    newLinks = [
                        url
                        for url in extraWarcLinks
                        if url not in existingUrls and url not in linksFound
                    ]
                    if len(newLinks) > 0:
                        with open(urlFilePath, "a") as f:
                            for url in newLinks:
                                f.write(url + "\n")

                        # Display message about extra links
                        write(
                            colored("GhostArchive - [ INFO ] ", "cyan")
                            + colored(str(len(newLinks)), "white")
                            + colored(" extra links found in WARC files added to file ", "cyan")
                            + colored(urlFilePath, "white")
                            + "\n"
                        )
            except Exception as e:
                if verbose():
                    writerr(colored("ERROR processResponsesGhostArchive 6: " + str(e), "red"))

        totalFileCount = totalFileCount + fileCount
    except Exception as e:
        writerr(colored(getSPACER("ERROR processResponsesGhostArchive 1: " + str(e)), "red"))
    finally:
        linkRequests = None


def processResponsesURLScan():
    """
    Get archived responses from URLScan (urlscan.io)
    """
    global subs, path, indexFile, totalResponses, stopProgram, argsInput, continueRespFileURLScan, successCount, fileCount, DEFAULT_OUTPUT_DIR, responseOutputDirectory, urlscanRequestLinks, failureCount, totalFileCount, checkURLScan
    try:
        fileCount = 0
        failureCount = 0
        if not args.check_only:
            # Create 'results' and domain directory if needed
            createDirs()

            # Get the path of the files, depending on whether -oR / --output_responses was passed
            try:
                continuePath = responseOutputDirectory + "continueRes.URLScan.tmp"
                responsesPath = responseOutputDirectory + "responses.URLScan.tmp"
                indexPath = responseOutputDirectory + "waymore_index.txt"
            except Exception as e:
                if verbose():
                    writerr(colored("ERROR processResponsesURLScan 4: " + str(e), "red"))

        # Get URLs from URLScan.io if the DOM ID's haven't been retrieved yet
        if stopProgram is None and not args.check_only:
            if args.mode in ("R", "B"):
                write(
                    colored(
                        "URLScan - [ INFO ] Getting list of response links (this can take a while for some domains)...",
                        "cyan",
                    )
                )
            if args.mode == "R":
                getURLScanUrls()

        # Check if a continueResp.URLScan.tmp and responses.URLScan.tmp files exists
        runPrevious = "n"
        if not args.check_only and os.path.exists(continuePath) and os.path.exists(responsesPath):

            # Load the links into the set
            with open(responsesPath, "rb") as fl:
                linkRequests = pickle.load(fl)
            totalPrevResponses = len(linkRequests)

            # Get the previous end position to start again at this point
            try:
                with open(continuePath) as fc:
                    successCount = int(fc.readline().strip())
            except Exception:
                successCount = 0

            # Ask the user if we should continue with previous run if the current starting position is greater than 0 and less than the total
            if successCount > 0 and successCount < totalPrevResponses:
                # If the program is not piped from or to another process, then ask whether to continue with previous run
                if sys.stdout.isatty() and sys.stdin.isatty():
                    write(
                        colored(
                            "The previous run to get archived responses for "
                            + argsInput
                            + " was not completed.\nYou can start from response "
                            + str(successCount)
                            + " of "
                            + str(totalPrevResponses)
                            + " for the previous run, or you can start a new run with your specified arguments.",
                            "yellow",
                        )
                    )
                    runPrevious = input("Continue with previous run? y/n: ")
                else:
                    if CONTINUE_RESPONSES_IF_PIPED:
                        runPrevious = "y"
                        writerr(
                            colored(
                                "The previous run to get archived responses for "
                                + argsInput
                                + " was not completed. Starting from response "
                                + str(successCount)
                                + " of "
                                + str(totalPrevResponses)
                                + "... ",
                                "yellow",
                            )
                        )
                    else:
                        runPrevious = "n"

        # If we are going to run a new run
        if runPrevious.lower() == "n":

            # Set start point
            successCount = 0

            # Get the URLScan DOM links
            linkRequests = []
            for originalUrl, domUrl in urlscanRequestLinks:
                linkRequests.append((originalUrl, domUrl))

            # Write the links to a temp file
            if not args.check_only:
                with open(responsesPath, "wb") as f:
                    pickle.dump(linkRequests, f)

        # Get the total number of responses we will try to get and set the current file count to the success count
        totalResponses = len(linkRequests)
        checkURLScan = checkURLScan + totalResponses

        # If there are no reponses to download, diaplay an error and exit
        if args.mode != "R" and totalResponses == 0:
            writerr(
                colored(
                    getSPACER(
                        "Failed to get responses from URLScan (urlscan.io) - check input and try again."
                    ),
                    "red",
                )
            )
            return

        fileCount = successCount

        if args.check_only:
            writerr(
                colored("Downloading archived responses: ", "cyan")
                + colored("UNKNOWN requests", "cyan")
            )
            writerr(
                colored(
                    "\n-> Downloading the responses can vary depending on the target and the rate limiting on URLScan",
                    "green",
                )
            )
            write("")
        else:
            # If the limit has been set over the default, give a warning that this could take a long time!
            if totalResponses - successCount > DEFAULT_LIMIT:
                if successCount > 0:
                    writerr(
                        colored(
                            getSPACER(
                                "WARNING: Downloading remaining "
                                + str(totalResponses - successCount)
                                + " responses may take a loooooooong time! Consider using arguments -ko, -l, -ci, -from and -to wisely!"
                            ),
                            "yellow",
                        )
                    )
                else:
                    writerr(
                        colored(
                            getSPACER(
                                "WARNING: Downloading "
                                + str(totalResponses)
                                + " responses may take a loooooooong time! Consider using arguments -ko, -l, -ci, -from and -to wisely!"
                            ),
                            "yellow",
                        )
                    )

            # Open the index file if hash value is going to be used (not URL)
            if not args.url_filename:
                indexFile = open(indexPath, "a")

            # Open the continue.URLScan.tmp file to store what record we are upto
            continueRespFileURLScan = open(continuePath, "w+")

            # Process the URLs from URLScan
            if stopProgram is None:
                p = mp.Pool(args.processes)
                p.starmap(getURLScanDOM, linkRequests[successCount:])
                p.close()
                p.join()

            # Delete the tmp files now it has run successfully
            if stopProgram is None:
                try:
                    os.remove(continuePath)
                    os.remove(responsesPath)
                except Exception:
                    pass

            # Close the index file if hash value is going to be used (not URL)
            if not args.url_filename:
                indexFile.close()

            # Close the continueResp.URLScan.tmp file
            continueRespFileURLScan.close()

        if not args.check_only:
            try:
                if failureCount > 0:
                    if verbose():
                        write(
                            colored("URLScan - [ INFO ] Responses saved to ", "cyan")
                            + colored(responseOutputDirectory, "white")
                            + colored(" for " + subs + argsInput + ": ", "cyan")
                            + colored(
                                str(fileCount)
                                + " ("
                                + str(successCount - fileCount)
                                + " empty responses) 🤘",
                                "white",
                            )
                            + colored(" (" + str(failureCount) + " not found)\n", "red")
                        )
                    else:
                        write(
                            colored(
                                "URLScan - [ INFO ] Responses saved for " + subs + argsInput + ": ",
                                "cyan",
                            )
                            + colored(
                                str(fileCount)
                                + " ("
                                + str(successCount - fileCount)
                                + " empty responses) 🤘",
                                "white",
                            )
                            + colored(" (" + str(failureCount) + " not found)\n", "red")
                        )
                else:
                    if verbose():
                        write(
                            colored(
                                "URLScan - [ INFO ] Responses saved for " + subs + argsInput + ": ",
                                "cyan",
                            )
                            + colored(responseOutputDirectory, "white")
                            + colored(" for " + subs + argsInput + ": ", "cyan")
                            + colored(
                                str(fileCount)
                                + " ("
                                + str(successCount - fileCount)
                                + " empty responses) 🤘\n",
                                "white",
                            )
                        )
                    else:
                        write(
                            colored(
                                "URLScan - [ INFO ] Responses saved for " + subs + argsInput + ": ",
                                "cyan",
                            )
                            + colored(
                                str(fileCount)
                                + " ("
                                + str(successCount - fileCount)
                                + " empty responses) 🤘\n",
                                "white",
                            )
                        )
            except Exception as e:
                if verbose():
                    writerr(colored("ERROR processResponsesURLScan 5: " + str(e), "red"))

        totalFileCount = totalFileCount + fileCount
    except Exception as e:
        writerr(colored(getSPACER("ERROR processResponsesURLScan 1: " + str(e)), "red"))
    finally:
        linkRequests = None


def processResponsesWayback():
    """
    Get archived responses from Wayback Machine (archive.org)
    """
    global linksFound, subs, path, indexFile, totalResponses, stopProgram, argsInput, continueRespFile, successCount, fileCount, DEFAULT_OUTPUT_DIR, responseOutputDirectory, failureCount, totalFileCount, current_response, current_session
    try:
        fileCount = 0
        failureCount = 0
        if not args.check_only:
            # Create 'results' and domain directory if needed
            createDirs()

            # Get the path of the files, depending on whether -oR / --output_responses was passed
            try:
                continuePath = responseOutputDirectory + "continueResp.tmp"
                responsesPath = responseOutputDirectory + "responses.tmp"
                indexPath = responseOutputDirectory + "waymore_index.txt"
            except Exception as e:
                if verbose():
                    writerr(colored("ERROR processResponsesWayback 4: " + str(e), "red"))

        # Check if a continueResp.tmp and responses.tmp files exists
        runPrevious = "n"
        if not args.check_only and os.path.exists(continuePath) and os.path.exists(responsesPath):

            # Load the links into the set
            with open(responsesPath, "rb") as fl:
                linkRequests = pickle.load(fl)
            totalPrevResponses = len(linkRequests)

            # Get the previous end position to start again at this point
            try:
                with open(continuePath) as fc:
                    successCount = int(fc.readline().strip())
            except Exception:
                successCount = 0

            # Ask the user if we should continue with previous run if the current starting position is greater than 0 and less than the total
            if successCount > 0 and successCount < totalPrevResponses:
                # If the program is not piped from or to another process, then ask whether to continue with previous run
                if sys.stdout.isatty() and sys.stdin.isatty():
                    write(
                        colored(
                            "The previous run to get archived responses for "
                            + argsInput
                            + " was not completed.\nYou can start from response "
                            + str(successCount)
                            + " of "
                            + str(totalPrevResponses)
                            + " for the previous run, or you can start a new run with your specified arguments.",
                            "yellow",
                        )
                    )
                    runPrevious = input("Continue with previous run? y/n: ")
                else:
                    if CONTINUE_RESPONSES_IF_PIPED:
                        runPrevious = "y"
                        writerr(
                            colored(
                                "The previous run to get archived responses for "
                                + argsInput
                                + " was not completed. Starting from response "
                                + str(successCount)
                                + " of "
                                + str(totalPrevResponses)
                                + "... ",
                                "yellow",
                            )
                        )
                    else:
                        runPrevious = "n"

        # If we are going to run a new run
        if runPrevious.lower() == "n":

            # Set start point
            successCount = 0

            # Set up filters
            filterLimit = "&limit=" + str(args.limit)
            if args.from_date is None:
                filterFrom = ""
            else:
                filterFrom = "&from=" + str(args.from_date)
            if args.to_date is None:
                filterTo = ""
            else:
                filterTo = "&to=" + str(args.to_date)

            # Set keywords filter if -ko argument passed
            filterKeywords = ""
            if args.keywords_only:
                if args.keywords_only == "#CONFIG":
                    filterKeywords = cdxKeywordsFilter(re.escape(FILTER_KEYWORDS).replace(",", "|"))
                else:
                    filterKeywords = cdxKeywordsFilter(args.keywords_only)

            # Get the list again with filters and include timestamp
            linksFound = set()

            # Set mime content type filter
            filterMIME = ""
            if MATCH_MIME.strip() != "":
                filterMIME = "&filter=mimetype:" + re.escape(MATCH_MIME).replace(",", "|")
            else:
                filterMIME = "&filter=!mimetype:warc/revisit"
                filterMIME = filterMIME + "|" + re.escape(FILTER_MIME).replace(",", "|")

            # Set status code filter
            filterCode = ""
            if MATCH_CODE.strip() != "":
                filterCode = "&filter=statuscode:" + re.escape(MATCH_CODE).replace(",", "|")
            else:
                filterCode = "&filter=!statuscode:" + re.escape(FILTER_CODE).replace(",", "|")

            # Set the collapse parameter value in the archive.org URL. From the Wayback API docs:
            # "A new form of filtering is the option to 'collapse' results based on a field, or a substring of a field.
            # Collapsing is done on adjacent cdx lines where all captures after the first one that are duplicate are filtered out.
            # This is useful for filtering out captures that are 'too dense' or when looking for unique captures."
            if args.capture_interval == "none":  # get all
                collapse = ""
            elif args.capture_interval == "h":  # get at most 1 capture per URL per hour
                collapse = "&collapse=timestamp:10"
            elif args.capture_interval == "d":  # get at most 1 capture per URL per day
                collapse = "&collapse=timestamp:8"
            elif args.capture_interval == "m":  # get at most 1 capture per URL per month
                collapse = "&collapse=timestamp:6"

            url = (
                WAYBACK_URL.replace("{DOMAIN}", subs + quote(argsInput) + path).replace(
                    "{COLLAPSE}", collapse
                )
                + filterMIME
                + filterCode
                + filterLimit
                + filterFrom
                + filterTo
                + filterKeywords
            )

            if verbose():
                write(
                    colored(
                        "Wayback - [ INFO ] The URL requested to get responses: ",
                        "magenta",
                    )
                    + colored(url + "\n", "white")
                )

            if args.check_only:
                write(colored("Wayback - [ INFO ] Checking archived response requests...", "cyan"))
            else:
                write(
                    colored(
                        "Wayback - [ INFO ] Getting list of response links (this can take a while for some domains)...",
                        "cyan",
                    )
                )

            # Build the list of links, concatenating timestamp and URL
            try:
                # Choose a random user agent string to use for any requests
                success = True
                userAgent = random.choice(USER_AGENT)
                session = requests.Session()
                session.mount("https://", HTTP_ADAPTER)
                session.mount("http://", HTTP_ADAPTER)
                try:
                    current_session = session
                except Exception:
                    pass
                resp = session.get(
                    url,
                    stream=True,
                    headers={"User-Agent": userAgent},
                    timeout=args.timeout,
                )
                try:
                    current_response = resp
                except Exception:
                    pass
            except ConnectionError:
                writerr(
                    colored(
                        getSPACER("Wayback - [ ERR ] Connection error"),
                        "red",
                    )
                )
                resp = None
                success = False
                return
            except Exception as e:
                writerr(
                    colored(
                        getSPACER("Wayback - [ ERR ] Couldn't get list of responses: " + str(e)),
                        "red",
                    )
                )
                resp = None
                success = False
                return
            finally:
                try:
                    if resp is not None:
                        # If the response from archive.org is empty, then no responses were found
                        if resp.text == "":
                            writerr(
                                colored(
                                    getSPACER(
                                        "Wayback - [ ERR ] No archived responses were found on Wayback Machine (archive.org) for the given search parameters."
                                    ),
                                    "red",
                                )
                            )
                            success = False
                        # If a status other of 429, then stop processing
                        if resp.status_code == 429:
                            writerr(
                                colored(
                                    getSPACER(
                                        "Wayback - [ 429 ] Wayback Machine (archive.org) rate limit reached, so stopping. Links that have already been retrieved will be saved."
                                    ),
                                    "red",
                                )
                            )
                            success = False
                        # If a status other of 503, then the site is unavailable
                        elif resp.status_code == 503:
                            writerr(
                                colored(
                                    getSPACER(
                                        "Wayback - [ 503 ] Wayback Machine (archive.org) is currently unavailable. It may be down for maintenance. You can check https://web.archive.org/cdx/ to verify."
                                    ),
                                    "red",
                                )
                            )
                            success = False
                        # If a status other than 200, then stop
                        elif resp.status_code != 200:
                            if verbose():
                                writerr(
                                    colored(
                                        getSPACER(
                                            "Wayback - [ "
                                            + str(resp.status_code)
                                            + " ] Error for "
                                            + url
                                        ),
                                        "red",
                                    )
                                )
                            success = False
                    if not success:
                        if args.keywords_only:
                            if args.keywords_only == "#CONFIG":
                                writerr(
                                    colored(
                                        getSPACER(
                                            "Wayback - [ ERR ] Failed to get links from Wayback Machine (archive.org) - consider removing -ko / --keywords-only argument, or changing FILTER_KEYWORDS in config.yml"
                                        ),
                                        "red",
                                    )
                                )
                            else:
                                writerr(
                                    colored(
                                        getSPACER(
                                            "Wayback - [ ERR ] Failed to get links from Wayback Machine (archive.org) - consider removing -ko / --keywords-only argument, or changing the Regex value you passed"
                                        ),
                                        "red",
                                    )
                                )
                        else:
                            if resp.text.lower().find("blocked site error") > 0:
                                writerr(
                                    colored(
                                        getSPACER(
                                            "Wayback - [ ERR ] Failed to get links from Wayback Machine (archive.org) - Blocked Site Error (they block the target site)"
                                        ),
                                        "red",
                                    )
                                )
                            else:
                                writerr(
                                    colored(
                                        getSPACER(
                                            "Wayback - [ ERR ] Failed to get links from Wayback Machine (archive.org) - check input domain and try again."
                                        ),
                                        "red",
                                    )
                                )
                        return
                except Exception:
                    pass

            # Go through the response to save the links found
            try:
                for line in resp.iter_lines():
                    try:
                        results = line.decode("utf-8")
                        parts = results.split(" ", 2)
                        timestamp = parts[0]
                        originalUrl = parts[1]
                        linksFoundResponseAdd(timestamp + "/" + originalUrl)
                    except Exception:
                        writerr(
                            colored(
                                getSPACER(
                                    "ERROR processResponsesWayback 3: Cannot to get link from line: "
                                    + str(line)
                                ),
                                "red",
                            )
                        )
            finally:
                try:
                    current_response = None
                except Exception:
                    pass
                try:
                    current_session = None
                except Exception:
                    pass

            # Cleanup shared response/session references now the response has been processed
            try:
                current_response = None
            except Exception:
                pass
            try:
                current_session = None
            except Exception:
                pass

            # Remove any links that have URL exclusions
            linkRequests = []
            exclusionRegex = re.compile(
                r"(" + re.escape(FILTER_URL).replace(",", "|") + ")",
                flags=re.IGNORECASE,
            )
            for link in linksFound:
                # Only add the link if:
                # a) if the -ra --regex-after was passed that it matches that
                # b) it does not match the URL exclusions
                if (
                    args.regex_after is None
                    or re.search(args.regex_after, link, flags=re.IGNORECASE) is not None
                ) and exclusionRegex.search(link) is None:
                    linkRequests.append(link)

            # Write the links to a temp file
            if not args.check_only:
                with open(responsesPath, "wb") as f:
                    pickle.dump(linkRequests, f)

        # Get the total number of responses we will try to get and set the current file count to the success count
        totalResponses = len(linkRequests)

        # If there are no reponses to download, diaplay an error and exit
        if totalResponses == 0:
            try:
                if originalUrl:
                    writerr(
                        colored(
                            getSPACER(
                                'Wayback - [ ERR ] Failed to get links from Wayback Machine (archive.org) - there were results (e.g. "'
                                + originalUrl
                                + "\") but they didn't match the input you gave. Check input and try again."
                            ),
                            "red",
                        )
                    )
            except Exception:
                writerr(
                    colored(
                        getSPACER(
                            "Wayback - [ ERR ] Failed to get links from Wayback Machine (archive.org) - check input and try again."
                        ),
                        "red",
                    )
                )
            return

        fileCount = successCount

        if args.check_only:
            if args.limit == 5000 and totalResponses + 1 == 5000:
                writerr(
                    colored("Downloading archived responses: ", "cyan")
                    + colored(
                        str(totalResponses + 1)
                        + " requests (the --limit argument defaults to "
                        + str(DEFAULT_LIMIT)
                        + ")",
                        "cyan",
                    )
                )
            else:
                writerr(
                    colored("Downloading archived responses: ", "cyan")
                    + colored(str(totalResponses + 1) + " requests", "white")
                )
            minutes = round(totalResponses * 2.5 // 60)
            hours = minutes // 60
            days = hours // 24
            if minutes < 5:
                write(
                    colored(
                        "\n-> Downloading the responses (depending on their size) should be quite quick!",
                        "green",
                    )
                )
            elif hours < 2:
                write(
                    colored(
                        "\n-> Downloading the responses (depending on their size) could take more than "
                        + str(minutes)
                        + " minutes.",
                        "green",
                    )
                )
            elif hours < 6:
                write(
                    colored(
                        "\n-> Downloading the responses (depending on their size) could take more than "
                        + str(hours)
                        + " hours.",
                        "green",
                    )
                )
            elif hours < 24:
                write(
                    colored(
                        "\n-> Downloading the responses (depending on their size) could take more than "
                        + str(hours)
                        + " hours.",
                        "yellow",
                    )
                )
            elif days < 7:
                write(
                    colored(
                        "\n-> Downloading the responses (depending on their size) could take more than "
                        + str(days)
                        + " days. Consider using arguments -ko, -l, -ci, -from and -to wisely! ",
                        "red",
                    )
                )
            else:
                write(
                    colored(
                        "\n-> Downloading the responses (depending on their size) could take more than "
                        + str(days)
                        + " days!!! Consider using arguments -ko, -l, -ci, -from and -to wisely!",
                        "red",
                    )
                )
            write("")
        else:
            # If the limit has been set over the default, give a warning that this could take a long time!
            if totalResponses - successCount > DEFAULT_LIMIT:
                if successCount > 0:
                    writerr(
                        colored(
                            getSPACER(
                                "WARNING: Downloading remaining "
                                + str(totalResponses - successCount)
                                + " responses may take a loooooooong time! Consider using arguments -ko, -l, -ci, -from and -to wisely!"
                            ),
                            "yellow",
                        )
                    )
                else:
                    writerr(
                        colored(
                            getSPACER(
                                "WARNING: Downloading "
                                + str(totalResponses)
                                + " responses may take a loooooooong time! Consider using arguments -ko, -l, -ci, -from and -to wisely!"
                            ),
                            "yellow",
                        )
                    )

            # Open the index file if hash value is going to be used (not URL)
            if not args.url_filename:
                indexFile = open(indexPath, "a")

            # Open the continueResp.tmp file to store what record we are upto
            continueRespFile = open(continuePath, "w+")

            # Process the URLs from web archive
            if stopProgram is None:
                p = mp.Pool(args.processes)
                p.map(processArchiveUrl, linkRequests[successCount:])
                p.close()
                p.join()

            # Delete the tmp files now it has run successfully
            if stopProgram is None:
                try:
                    os.remove(continuePath)
                    os.remove(responsesPath)
                except Exception:
                    pass

            # Close the index file if hash value is going to be used (not URL)
            if not args.url_filename:
                indexFile.close()

            # Close the continueResp.tmp file
            continueRespFile.close()

        # Output results if not just checking
        if not args.check_only:
            try:
                if failureCount > 0:
                    if verbose():
                        write(
                            colored("Wayback - [ INFO ] Responses saved to ", "cyan")
                            + colored(responseOutputDirectory, "white")
                            + colored(" for " + subs + argsInput + ": ", "cyan")
                            + colored(
                                str(fileCount)
                                + " ("
                                + str(successCount - fileCount)
                                + " empty responses) 🤘",
                                "white",
                            )
                            + colored(" (" + str(failureCount) + " failed)\n", "red")
                        )
                    else:
                        write(
                            colored(
                                "Wayback - [ INFO ] Responses saved for " + subs + argsInput + ": ",
                                "cyan",
                            )
                            + colored(
                                str(fileCount)
                                + " ("
                                + str(successCount - fileCount)
                                + " empty responses) 🤘",
                                "white",
                            )
                            + colored(" (" + str(failureCount) + " failed)\n", "red")
                        )
                else:
                    if verbose():
                        write(
                            colored("Wayback - [ INFO ] Responses saved to ", "cyan")
                            + colored(responseOutputDirectory, "white")
                            + colored(" for " + subs + argsInput + ": ", "cyan")
                            + colored(
                                str(fileCount)
                                + " ("
                                + str(successCount - fileCount)
                                + " empty responses) 🤘\n",
                                "white",
                            )
                        )
                    else:
                        write(
                            colored(
                                "Wayback - [ INFO ] Responses saved for " + subs + argsInput + ": ",
                                "cyan",
                            )
                            + colored(
                                str(fileCount)
                                + " ("
                                + str(successCount - fileCount)
                                + " empty responses) 🤘\n",
                                "white",
                            )
                        )
            except Exception as e:
                if verbose():
                    writerr(colored("ERROR processResponsesWayback 5: " + str(e), "red"))

        totalFileCount = totalFileCount + fileCount
    except Exception as e:
        writerr(colored(getSPACER("ERROR processResponsesWayback 1: " + str(e)), "red"))
    finally:
        linkRequests = None


def createDirs():
    """
    Create a directory for the 'results' and the sub directory for the passed domain/URL, unless if
    -oR / --output-responses was passed, just create those directories
    """
    global DEFAULT_OUTPUT_DIR, argsInput
    try:
        if (args.mode in "R,B" and args.output_responses == "") or (
            args.mode in "U,B" and args.output_urls == ""
        ):
            # Create a directory for "results" if it doesn't already exist
            try:
                results_dir = Path(DEFAULT_OUTPUT_DIR + "/results")
                results_dir.mkdir(exist_ok=True)
            except Exception:
                pass
            # Create a directory for the target domain
            try:
                domain_dir = Path(
                    DEFAULT_OUTPUT_DIR + "/results/" + str(argsInput).replace("/", "-")
                )
                domain_dir.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
        try:
            # Create specified directory for -oR if required
            if args.output_responses != "":
                responseDir = Path(args.output_responses)
                responseDir.mkdir(parents=True, exist_ok=True)
            # If -oU was passed and is prefixed with a directory, create it
            if args.output_urls != "" and "/" in args.output_urls:
                directoriesOnly = os.path.dirname(args.output_urls)
                responseDir = Path(directoriesOnly)
                responseDir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
    except Exception as e:
        writerr(colored(getSPACER("ERROR createDirs 1: " + str(e)), "red"))


# Get width of the progress bar based on the width of the terminal
def getProgressBarLength():
    global terminalWidth
    try:
        if verbose():
            offset = 90
        else:
            offset = 50
        progressBarLength = terminalWidth - offset
    except Exception:
        progressBarLength = 20
    return progressBarLength


# Get the length of the space to add to a string to fill line up to width of terminal
def getSPACER(text):
    global terminalWidth
    lenSpacer = terminalWidth - len(text) + 5
    SPACER = " " * lenSpacer
    return text + SPACER


# For validating -m / --memory-threshold argument


def notifyDiscord():
    global WEBHOOK_DISCORD, args
    try:
        data = {
            "content": "waymore has finished for `-i "
            + args.input
            + " -mode "
            + args.mode
            + "` ! 🤘",
            "username": "waymore",
        }
        try:
            session = requests.Session()
            if HTTP_ADAPTER is not None:
                session.mount("https://", HTTP_ADAPTER)
                session.mount("http://", HTTP_ADAPTER)
            result = session.post(WEBHOOK_DISCORD, json=data)
            if 300 <= result.status_code < 200:
                writerr(
                    colored(
                        getSPACER(
                            "WARNING: Failed to send notification to Discord - " + result.json()
                        ),
                        "yellow",
                    )
                )
        except Exception as e:
            writerr(
                colored(
                    getSPACER("WARNING: Failed to send notification to Discord - " + str(e)),
                    "yellow",
                )
            )
    except Exception as e:
        writerr(colored("ERROR notifyDiscord 1: " + str(e), "red"))


def notifyTelegram():
    global TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, args
    try:
        url = "https://api.telegram.org/bot" + TELEGRAM_BOT_TOKEN + "/sendMessage"
        data = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": "waymore has finished for `-i " + args.input + " -mode " + args.mode + "` ! 🤘",
        }
        try:
            session = requests.Session()
            if HTTP_ADAPTER is not None:
                session.mount("https://", HTTP_ADAPTER)
                session.mount("http://", HTTP_ADAPTER)
            result = session.post(url, json=data)
            if 300 <= result.status_code < 200:
                writerr(
                    colored(
                        getSPACER(
                            "WARNING: Failed to send notification to Telegram - " + result.json()
                        ),
                        "yellow",
                    )
                )
        except Exception as e:
            writerr(
                colored(
                    getSPACER("WARNING: Failed to send notification to Telegram - " + str(e)),
                    "yellow",
                )
            )
    except Exception as e:
        writerr(colored("ERROR notifyTelegram 1: " + str(e), "red"))




def extractScripts(filePath):
    try:
        with open(filePath, "rb") as file:
            content = file.read().decode("utf-8", errors="ignore")
            scripts = re.findall(r"<script[^>]*>(.*?)</script>", content, re.DOTALL)
            scripts = list(filter(checkScript, scripts))
            return scripts
    except Exception as e:
        writerr(colored("ERROR extractScripts 1: " + str(e), "red"))


def extractExternalScripts(filePath):
    try:
        with open(filePath, "rb") as file:
            content = file.read().decode("utf-8", errors="ignore")
            scripts = re.findall(r'<script[^>]* src="(.*?)".*?>', content, re.DOTALL)
            scripts = list(filter(checkScript, scripts))
            return scripts
    except Exception as e:
        writerr(colored("ERROR extractExternalScripts 1: " + str(e), "red"))


def combineInlineJS():
    global responseOutputDirectory, INLINE_JS_EXCLUDE
    try:
        write(colored("Creating combined inline JS files...", "cyan"))
        outputFileTemplate = "combinedInline{}.js"
        excludedNames = [
            "waymore_index.txt",
            "continueResp.tmp",
            "continueResp.URLScan.tmp",
            "responses.tmp",
            "responses.URLScan.tmp",
        ]
        fileList = [
            name
            for name in os.listdir(responseOutputDirectory)
            if os.path.isfile(os.path.join(responseOutputDirectory, name))
            and not any(name.lower().endswith(ext) for ext in INLINE_JS_EXCLUDE)
            and name not in excludedNames
            and "combinedInline" not in name
        ]

        allScripts = {}  # To store all scripts from all files
        allExternalScripts = []  # To store all external script sources from all files

        fileCount = len(fileList)
        currentFile = 1
        for filename in fileList:
            filePath = os.path.join(responseOutputDirectory, filename)
            scripts = extractScripts(filePath)
            if scripts:
                allScripts[filename] = scripts
            allExternalScripts.extend(extractExternalScripts(filePath))

            # Show progress bar
            fillTest = currentFile % 2
            fillChar = "o"
            if fillTest == 0:
                fillChar = "O"
            suffix = "Complete "
            printProgressBar(
                currentFile,
                fileCount,
                prefix="Checking " + str(fileCount) + " files:",
                suffix=suffix,
                length=getProgressBarLength(),
                fill=fillChar,
            )
            currentFile += 1

        # Write a file of external javascript files referenced in the inline scripts
        totalExternal = len(allExternalScripts)
        if totalExternal > 0:
            uniqueExternalScripts = set(allExternalScripts)
            outputFile = os.path.join(responseOutputDirectory, "combinedInlineSrc.txt")
            inlineExternalFile = open(outputFile, "w", encoding="utf-8")
            for script in uniqueExternalScripts:
                inlineExternalFile.write(script.strip() + "\n")
            write(
                colored("Created file ", "cyan")
                + colored(responseOutputDirectory + "combinedInlineSrc.txt", "white")
                + colored(" (src of external JS)", "cyan")
            )
        else:
            write(
                colored(
                    "No external JS scripts found, so no combined Inline Src file written.\n",
                    "cyan",
                )
            )

        # Write files for all combined inline JS
        uniqueScripts = set()
        for scriptsList in allScripts.values():
            uniqueScripts.update(scriptsList)

        totalSections = len(uniqueScripts)
        sectionCounter = 0  # Counter for inline JS sections
        currentOutputFile = os.path.join(responseOutputDirectory, outputFileTemplate.format(1))
        currentSectionsWritten = 0  # Counter for sections written in current file

        if totalSections > 0:
            fileNumber = 1
            with open(currentOutputFile, "w", encoding="utf-8") as inlineJSFile:
                currentScript = 1
                for script in uniqueScripts:
                    # Show progress bar
                    fillTest = currentScript % 2
                    fillChar = "o"
                    if fillTest == 0:
                        fillChar = "O"
                    suffix = "Complete "
                    printProgressBar(
                        currentScript,
                        totalSections,
                        prefix="Writing " + str(totalSections) + " unique scripts:",
                        suffix=suffix,
                        length=getProgressBarLength(),
                        fill=fillChar,
                    )
                    sectionCounter += 1
                    currentSectionsWritten += 1
                    if currentSectionsWritten > 1000:
                        # If 1000 sections have been written, switch to the next output file
                        inlineJSFile.close()
                        fileNumber = sectionCounter // 1000 + 1
                        currentOutputFile = os.path.join(
                            responseOutputDirectory,
                            outputFileTemplate.format(fileNumber),
                        )
                        inlineJSFile = open(currentOutputFile, "w", encoding="utf-8")
                        currentSectionsWritten = 1

                    # Insert comment line for the beginning of the section
                    inlineJSFile.write(f"//****** INLINE JS SECTION {sectionCounter} ******//\n\n")

                    # Write comments indicating the files the script was found in
                    files = ""
                    for filename, scripts_list in allScripts.items():
                        if script in scripts_list:
                            files = files + filename + ", "

                    # Write the files the script appears in
                    inlineJSFile.write("// " + files.rstrip(", ") + "\n")

                    # Write the script content
                    inlineJSFile.write("\n" + script.strip() + "\n\n")

                    currentScript += 1

        if totalSections == 0:
            write(
                colored(
                    "No scripts found, so no combined Inline JS files written.\n",
                    "cyan",
                )
            )
        else:
            if fileNumber == 1:
                write(
                    colored("Created file ", "cyan")
                    + colored(responseOutputDirectory + "combinedInline1.js", "white")
                    + colored(" (contents of inline JS)\n", "cyan")
                )
            else:
                write(
                    colored("Created files ", "cyan")
                    + colored(
                        responseOutputDirectory + "combinedInline{1-" + str(fileNumber) + "}.js",
                        "white",
                    )
                    + colored(" (contents of inline JS)\n", "cyan")
                )

    except Exception as e:
        writerr(colored("ERROR combineInlineJS 1: " + str(e), "red"))


# Async wrapper functions for concurrent source fetching
async def fetch_wayback_async():
    """Async wrapper for getWaybackUrls - runs in thread pool"""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, getWaybackUrls)


async def fetch_commoncrawl_async():
    """Async wrapper for getCommonCrawlUrls - runs in thread pool"""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, getCommonCrawlUrls)


async def fetch_alienvault_async():
    """Async wrapper for getAlienVaultUrls - runs in thread pool"""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, getAlienVaultUrls)


async def fetch_urlscan_async():
    """Async wrapper for getURLScanUrls - runs in thread pool"""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, getURLScanUrls)


async def fetch_virustotal_async():
    """Async wrapper for getVirusTotalUrls - runs in thread pool"""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, getVirusTotalUrls)


async def fetch_intelx_async():
    """Async wrapper for getIntelxUrls - runs in thread pool"""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, getIntelxUrls)


async def fetch_ghostarchive_async():
    """Async wrapper for getGhostArchiveUrls - runs in thread pool"""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, getGhostArchiveUrls)


async def fetch_all_sources_async():
    """
    Orchestrator function to fetch from all enabled sources concurrently.
    Each source runs in its own thread pool executor while orchestration happens async.
    """
    global args, stopProgram, VIRUSTOTAL_API_KEY, INTELX_API_KEY, argsInput

    tasks = []

    # Build list of tasks for enabled sources
    if not args.xwm and stopProgram is None:
        tasks.append(("Wayback Machine", fetch_wayback_async()))
    if not args.xcc and stopProgram is None:
        tasks.append(("Common Crawl", fetch_commoncrawl_async()))
    if not args.xav and stopProgram is None and not argsInput.startswith("."):
        tasks.append(("AlienVault OTX", fetch_alienvault_async()))
    if not args.xus and stopProgram is None:
        tasks.append(("URLScan", fetch_urlscan_async()))
    if not args.xvt and VIRUSTOTAL_API_KEY != "" and stopProgram is None:
        tasks.append(("VirusTotal", fetch_virustotal_async()))
    if not args.xix and INTELX_API_KEY != "" and stopProgram is None:
        tasks.append(("Intelligence X", fetch_intelx_async()))
    if not args.xga and stopProgram is None:
        tasks.append(("GhostArchive", fetch_ghostarchive_async()))

    if not tasks:
        return

    # Extract just the coroutines for gather
    task_coros = [task[1] for task in tasks]

    # Fetch all concurrently, capturing exceptions so one failure doesn't stop others
    results = await asyncio.gather(*task_coros, return_exceptions=True)

    # Check for any exceptions that occurred
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            source_name = tasks[i][0]
            if verbose():
                writerr(
                    colored(
                        getSPACER(f"ERROR in {source_name} during concurrent fetch: {str(result)}"),
                        "red",
                    )
                )


def ensureConfigExists():
    """
    Ensure the default config file exists before argument parsing.
    This is called at the very start of main() so the config is created
    even when running with -h or with no arguments.
    """
    try:
        # Determine the default config path based on the OS
        if os.name == "nt":
            waymoreCfgPath = Path(os.path.join(os.getenv("APPDATA", ""), "waymore"))
        elif sys.platform == "darwin":
            waymoreCfgPath = Path(os.path.expanduser("~/Library/Application Support/waymore"))
        else:
            waymoreCfgPath = Path(os.path.expanduser("~/.config/waymore"))

        configPath = waymoreCfgPath / "config.yml"

        if not os.path.isfile(configPath):
            # Make sure the directory exists
            os.makedirs(configPath.parent, exist_ok=True)
            # Create the default config content using the DEFAULT_* constants
            defaultConfig = f"""FILTER_CODE: {DEFAULT_FILTER_CODE}
FILTER_MIME: {DEFAULT_FILTER_MIME}
FILTER_URL: {DEFAULT_FILTER_URL}
FILTER_KEYWORDS: {DEFAULT_FILTER_KEYWORDS}
URLSCAN_API_KEY:
VIRUSTOTAL_API_KEY:
CONTINUE_RESPONSES_IF_PIPED: True
WEBHOOK_DISCORD: YOUR_WEBHOOK
TELEGRAM_BOT_TOKEN: YOUR_TOKEN
TELEGRAM_CHAT_ID: YOUR_CHAT_ID
DEFAULT_OUTPUT_DIR:
INTELX_API_KEY:
SOURCE_IP:
"""
            with open(configPath, "w", encoding="utf-8") as f:
                f.write(defaultConfig)
            writerr(
                colored(
                    'Config file not found - created default config at "' + str(configPath) + '"',
                    "yellow",
                )
            )
    except Exception as e:
        try:
            writerr(
                colored(
                    "Config file not found, but failed to create default config file: " + str(e),
                    "red",
                )
            )
        except Exception:
            pass


# Run waymore
def main():
    global args, DEFAULT_TIMEOUT, inputValues, argsInput, linksFound, linkMimes, successCount, failureCount, fileCount, totalResponses, totalPages, indexFile, path, stopSource, stopProgram, VIRUSTOTAL_API_KEY, inputIsSubDomain, argsInputHostname, WEBHOOK_DISCORD, responseOutputDirectory, fileCount, INTELX_API_KEY, stopSourceAlienVault, stopSourceCommonCrawl, stopSourceWayback, stopSourceURLScan, stopSourceVirusTotal, stopSourceIntelx, stopSourceGhostArchive, extraWarcLinks

    # Ensure the default config file exists before anything else
    ensureConfigExists()

    # Tell Python to run the handler() function when SIGINT is received
    signal(SIGINT, handler)

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="waymore - by @Xnl-h4ck3r: Find way more from the Wayback Machine"
    )
    parser.add_argument(
        "-i",
        "--input",
        action="store",
        help='The target domain (or file of domains) to find links for. This can be a domain only, or a domain with a specific path. If it is a domain only to get everything for that domain, don\'t prefix with "www."',
        type=validateArgInput,
    )
    parser.add_argument(
        "-n",
        "--no-subs",
        action="store_true",
        help="Don't include subdomains of the target domain (only used if input is not a domain with a specific path).",
    )
    parser.add_argument(
        "-mode",
        action="store",
        help="The mode to run: U (retrieve URLs only), R (download Responses only) or B (Both).",
        choices=["U", "R", "B"],
        default="B",
    )
    parser.add_argument(
        "-oU",
        "--output-urls",
        action="store",
        help='The file to save the Links output to, including path if necessary. If the "-oR" argument is not passed, a "results" directory will be created in the path specified by the DEFAULT_OUTPUT_DIR key in config.yml file (typically defaults to "~/.config/waymore/"). Within that, a directory will be created with target domain (or domain with path) passed with "-i" (or for each line of a file passed with "-i").',
        default="",
    )
    parser.add_argument(
        "-oR",
        "--output-responses",
        action="store",
        help='The directory to save the response output files to, including path if necessary. If the argument is not passed, a "results" directory will be created in the path specified by the DEFAULT_OUTPUT_DIR key in config.yml file (typically defaults to "~/.config/waymore/"). Within that, a directory will be created with target domain (or domain with path) passed with "-i" (or for each line of a file passed with "-i").',
        default="",
    )
    parser.add_argument(
        "-f",
        "--filter-responses-only",
        action="store_true",
        help="The initial links from Wayback Machine will not be filtered (MIME Type and Response Code), only the responses that are downloaded, e.g. it maybe useful to still see all available paths from the links even if you don't want to check the content.",
    )
    parser.add_argument(
        "-fc",
        action="store",
        help="Filter HTTP status codes for retrieved URLs and responses. Comma separated list of codes (default: the FILTER_CODE values from config.yml). Passing this argument will override the value from config.yml",
        type=validateArgStatusCodes,
    )
    parser.add_argument(
        "-ft",
        action="store",
        help="Filter MIME Types for retrieved URLs and responses. Comma separated list of MIME Types (default: the FILTER_MIME values from config.yml). Passing this argument will override the value from config.yml. NOTE: This will NOT be applied to Alien Vault OTX, Virus Total and Intelligence X because they don't have the ability to filter on MIME Type. Sometimes URLScan does not have a MIME Type defined - these will always be included. Consider excluding sources if this matters to you.",
        type=validateArgMimeTypes,
    )
    parser.add_argument(
        "-mc",
        action="store",
        help="Only Match HTTP status codes for retrieved URLs and responses. Comma separated list of codes. Passing this argument overrides the config FILTER_CODE and -fc.",
        type=validateArgStatusCodes,
    )
    parser.add_argument(
        "-mt",
        action="store",
        help="Only MIME Types for retrieved URLs and responses. Comma separated list of MIME types. Passing this argument overrides the config FILTER_MIME and -ft. NOTE: This will NOT be applied to Alien Vault OTX, Virus Total and Intelligence X because they don't have the ability to filter on MIME Type. Sometimes URLScan does not have a MIME Type defined - these will always be included. Consider excluding sources if this matters to you.",
        type=validateArgMimeTypes,
    )
    parser.add_argument(
        "-l",
        "--limit",
        action="store",
        type=int,
        help="How many responses will be saved (if -mode is R or B). A positive value will get the first N results, a negative value will will get the last N results. A value of 0 will get ALL responses (default: "
        + str(DEFAULT_LIMIT)
        + ")",
        default=DEFAULT_LIMIT,
        metavar="<signed integer>",
    )
    parser.add_argument(
        "-from",
        "--from-date",
        action="store",
        type=validateArgDate,
        help="What date to get responses from. If not specified it will get from the earliest possible results. A partial value can be passed, e.g. 2016, 201805, etc.",
        metavar="<yyyyMMddhhmmss>",
    )
    parser.add_argument(
        "-to",
        "--to-date",
        action="store",
        type=validateArgDate,
        help="What date to get responses to. If not specified it will get to the latest possible results. A partial value can be passed, e.g. 2016, 201805, etc.",
        metavar="<yyyyMMddhhmmss>",
    )
    parser.add_argument(
        "-ci",
        "--capture-interval",
        action="store",
        choices=["h", "d", "m", "none"],
        help="Filters the search on Wayback Machine (archive.org) to only get at most 1 capture per hour (h), day (d) or month (m). This filter is used for responses only. The default is 'd' but can also be set to 'none' to not filter anything and get all responses.",
        default="d",
    )
    parser.add_argument(
        "-ra",
        "--regex-after",
        help="RegEx for filtering purposes against links found all sources of URLs AND responses downloaded. Only positive matches will be output.",
        action="store",
    )
    parser.add_argument(
        "-url-filename",
        action="store_true",
        help="Set the file name of downloaded responses to the URL that generated the response, otherwise it will be set to the hash value of the response. Using the hash value means multiple URLs that generated the same response will only result in one file being saved for that response.",
        default=False,
    )
    parser.add_argument(
        "-xwm",
        action="store_true",
        help="Exclude checks for links from Wayback Machine (archive.org)",
        default=False,
    )
    parser.add_argument(
        "-xcc",
        action="store_true",
        help="Exclude checks for links from commoncrawl.org",
        default=False,
    )
    parser.add_argument(
        "-xav",
        action="store_true",
        help="Exclude checks for links from alienvault.com",
        default=False,
    )
    parser.add_argument(
        "-xus",
        action="store_true",
        help="Exclude checks for links from urlscan.io",
        default=False,
    )
    parser.add_argument(
        "-xvt",
        action="store_true",
        help="Exclude checks for links from virustotal.com",
        default=False,
    )
    parser.add_argument(
        "-xix",
        action="store_true",
        help="Exclude checks for links from intelx.io",
        default=False,
    )
    parser.add_argument(
        "-xga",
        action="store_true",
        help="Exclude checks for links from ghostarchive.org",
        default=False,
    )
    parser.add_argument(
        "--providers",
        action="store",
        help="A comma separated list of source providers that you want to get URLs from. The values can be wayback,commoncrawl,otx,urlscan,virustotal,intelx and ghostarchive. Passing this will override any exclude arguments (e.g. -xwm,-xcc, etc.) passed to exclude sources, and reset those based on what was passed with this argument.",
        default=[],
        type=validateArgProviders,
        metavar="{wayback,commoncrawl,otx,urlscan,virustotal,intelx,ghostarchive}",
    )
    parser.add_argument(
        "-lcc",
        action="store",
        type=int,
        help="Limit the number of Common Crawl index collections searched, e.g. '-lcc 10' will just search the latest 10 collections (default: 1). As of November 2024 there are currently 106 collections. Setting to 0 (default) will search ALL collections. If you don't want to search Common Crawl at all, use the -xcc option.",
        default=1,
    )
    parser.add_argument(
        "-t",
        "--timeout",
        help="This is for archived responses only! How many seconds to wait for the server to send data before giving up (default: "
        + str(DEFAULT_TIMEOUT)
        + " seconds)",
        default=DEFAULT_TIMEOUT,
        type=int,
        metavar="<seconds>",
    )
    parser.add_argument(
        "-p",
        "--processes",
        help="Basic multithreading is done when getting requests for a file of URLs. This argument determines the number of processes (threads) used (default: 2)",
        action="store",
        type=validateArgProcesses,
        default=2,
        metavar="<integer>",
    )
    parser.add_argument(
        "-r",
        "--retries",
        action="store",
        type=int,
        help="The number of retries for requests that get connection error or rate limited (default: 1).",
        default=1,
    )
    parser.add_argument(
        "-sip",
        "--source-ip",
        "--bind-ip",
        dest="source_ip",
        action="store",
        help="Bind outbound HTTP/HTTPS requests to this source IP (useful on multi-homed hosts).",
        type=validateArgIPAddress,
    )
    parser.add_argument(
        "-m",
        "--memory-threshold",
        action="store",
        help="The memory threshold percentage. If the machines memory goes above the threshold, the program will be stopped and ended gracefully before running out of memory (default: 95)",
        default=95,
        metavar="<integer>",
        type=argcheckPercent,
    )
    parser.add_argument(
        "-ko",
        "--keywords-only",
        action="store",
        help=r"Only return links and responses that contain keywords that you are interested in. This can reduce the time it takes to get results. If you provide the flag with no value, Keywords are taken from the comma separated list in the \"config.yml\" file with the \"FILTER_KEYWORDS\" key, otherwise you can pass a specific Python Regex value. e.g. -ko 'admin' to only get links containing the word admin, or -ko '\.js(\?.*|$)' to only get JS files. The Regex check is NOT case sensitive. NOTE: The pattern is used as an approximate pre-filter on the Wayback CDX API (wrapped as .*pattern.*, so anchors like $ may not behave as expected at the CDX level), then applied exactly as a Python regex locally. Use single quotes to avoid shell expansion of $ and other special characters.",
        nargs="?",
        const="#CONFIG",
    )
    parser.add_argument(
        "-lr",
        "--limit-requests",
        type=int,
        help="Limit the number of requests that will be made when getting links from a source (this doesn't apply to Common Crawl). Some targets can return a huge amount of requests needed that are just not feasible to get, so this can be used to manage that situation. This defaults to 0 (Zero) which means there is no limit.",
        default=0,
    )
    parser.add_argument(
        "-ow",
        "--output-overwrite",
        action="store_true",
        help="If the URL output file (default waymore.txt) already exists, it will be overwritten instead of being appended to.",
    )
    parser.add_argument(
        "-nlf",
        "--new-links-file",
        action="store_true",
        help="If this argument is passed, a .new file will also be written that will contain links for the latest run. This is only relevant for mode U.",
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Output URLs to STDOUT as soon as they are found (duplicates will be shown). Only works with -mode U. All other output is suppressed, so use -v to see any errors. Use -oU to explicitly save results to file (wil be deduplicated).",
    )
    parser.add_argument(
        "-c",
        "--config",
        action="store",
        help="Path to the YML config file. If not passed, it looks for file 'config.yml' in the same directory as runtime file 'waymore.py'.",
    )
    parser.add_argument(
        "-wrlr",
        "--wayback-rate-limit-retry",
        action="store",
        type=int,
        help="The number of minutes the user wants to wait for a rate limit pause on Watback Machine (archive.org) instead of stopping with a 429 error (default: 3).",
        default=3,
    )
    parser.add_argument(
        "-urlr",
        "--urlscan-rate-limit-retry",
        action="store",
        type=int,
        help="The number of minutes the user wants to wait for a rate limit pause on URLScan.io instead of stopping with a 429 error (default: 1).",
        default=1,
    )
    parser.add_argument(
        "-co",
        "--check-only",
        action="store_true",
        help="This will make a few minimal requests to show you how many requests, and roughly how long it could take, to get URLs from the sources and downloaded responses from Wayback Machine (unfortunately it isn't possible to check how long it will take to download responses from URLScan).",
    )
    parser.add_argument(
        "-nd",
        "--notify-discord",
        action="store_true",
        help="Whether to send a notification to Discord when waymore completes. It requires WEBHOOK_DISCORD to be provided in the config.yml file.",
    )
    parser.add_argument(
        "-nt",
        "--notify-telegram",
        action="store_true",
        help="Whether to send a notification to Telegram when waymore completes. It requires TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to be provided in the config.yml file.",
    )
    parser.add_argument(
        "-oijs",
        "--output-inline-js",
        action="store_true",
        help='Whether to save combined inline javascript of all relevant files in the response directory when "-mode R" (or "-mode B") has been used. The files are saved with the name "combined_inline{}.js" where "{}" is the number of the file, saving 1000 unique scripts per file. ',
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="store_true", help="Show version number")
    args = parser.parse_args()

    # If --version was passed, display version and exit
    if args.version:
        showVersion()
        sys.exit()

    # Validate -ra and -ko regex patterns early so corrupted patterns (e.g. from
    # bash $-expansion inside double-quoted strings) give a clear error instead of
    # silently returning zero results.
    if args.regex_after is not None:
        try:
            re.compile(args.regex_after)
        except re.error as e:
            writerr(
                colored(
                    f"ERROR: -ra / --regex-after value is not a valid regex: {e}\n"
                    "TIP: Use single quotes to avoid shell expansion, e.g. -ra '\\. js(\\?|$)'",
                    "red",
                )
            )
            sys.exit()
    if args.keywords_only is not None and args.keywords_only != "#CONFIG":
        try:
            re.compile(args.keywords_only)
        except re.error as e:
            writerr(
                colored(
                    f"ERROR: -ko / --keywords-only value is not a valid regex: {e}\n"
                    "TIP: Use single quotes to avoid shell expansion, e.g. -ko '\\. js(\\?|$)'",
                    "red",
                )
            )
            sys.exit()

    # If --providers was passed, then manually set the exclude arguments;
    if args.providers:
        if "wayback" not in args.providers:
            args.xwm = True
        else:
            args.xwm = False
        if "commoncrawl" not in args.providers:
            args.xcc = True
        else:
            args.xcc = False
        if "otx" not in args.providers:
            args.xav = True
        else:
            args.xav = False
        if "urlscan" not in args.providers:
            args.xus = True
        else:
            args.xus = False
        if "virustotal" not in args.providers:
            args.xvt = True
        else:
            args.xvt = False
        if "intelx" not in args.providers:
            args.xix = True
        else:
            args.xix = False
        if "ghostarchive" not in args.providers:
            args.xga = True
        else:
            args.xga = False

    # If no input was given, raise an error
    if sys.stdin.isatty():
        if args.input is None:
            writerr(
                colored(
                    "You need to provide an input with -i argument or through <stdin>.",
                    "red",
                )
            )
            sys.exit()
    else:
        validateArgInput("<stdin>")

    # Get the current Process ID to use to get memory usage that is displayed with -vv option
    global process
    try:
        process = psutil.Process(os.getpid())
    except Exception:
        pass

    if not (args.stream and args.mode == "U"):
        showBanner()

    try:

        # For each input (maybe multiple if a file was passed)
        for inpt in inputValues:

            # Strip and clean the input, but only lowercase the hostname (paths are case-sensitive)
            cleaned = inpt.strip().rstrip("\n").strip(".")
            if "/" in cleaned:
                hostname_part, path_part = cleaned.split("/", 1)
                argsInput = hostname_part.lower() + "/" + path_part
            else:
                argsInput = cleaned.lower()

            # Get the input hostname
            tldExtract = tldextract.extract(argsInput)
            subDomain = tldExtract.subdomain
            inputIsSubDomain = False
            if subDomain != "":
                inputIsSubDomain = True
                subDomain = subDomain + "."

            # Convert domain to punycode
            punyCode = tldExtract.domain.encode("idna").decode("ascii")
            if tldExtract.domain != punyCode:
                writerr(
                    colored(
                        getSPACER(
                            f"IMPORTANT:  You passed a domain that contains unicode characters, so this will be converted to Punycode when retrieving from archived sources, i.e. {punyCode}.{tldExtract.suffix}\n"
                        ),
                        "yellow",
                    )
                )
                argsInput = argsInput.replace(tldExtract.domain, punyCode)
                rootDomain = punyCode
            else:
                rootDomain = tldExtract.domain
            argsInputHostname = subDomain + rootDomain + "." + tldExtract.suffix

            # Warn user if a sub domains may have been passed
            if inputIsSubDomain:
                writerr(
                    colored(
                        getSPACER(
                            "IMPORTANT: It looks like you may be passing a subdomain. If you want ALL subs for a domain, then pass the domain only. It will be a LOT quicker, and you won't miss anything. NEVER pass a file of subdomains if you want everything, just the domains.\n"
                        ),
                        "yellow",
                    )
                )

            # Reset global variables
            linksFound = set()
            linkMimes = set()
            extraWarcLinks = set()
            successCount = 0
            failureCount = 0
            fileCount = 0
            totalResponses = 0
            totalPages = 0
            indexFile = None
            path = ""
            stopSource = False
            stopSourceWayback = False
            stopSourceCommonCrawl = False
            stopSourceAlienVault = False
            stopSourceURLScan = False
            stopSourceVirusTotal = False
            stopSourceIntelx = False
            stopSourceGhostArchive = False

            # Get the config settings from the config.yml file
            getConfig()

            if verbose() and not (args.stream and args.mode == "U"):
                showOptions()

            if args.check_only:
                write(
                    colored("*** Checking requests needed for ", "cyan")
                    + colored(argsInput, "white")
                    + colored(" ***\n", "cyan")
                )

            # If the mode is U (URLs retrieved) or B (URLs retrieved AND Responses downloaded)
            if args.mode in ["U", "B"]:

                # Fetch from all sources concurrently using async/await
                try:
                    asyncio.run(fetch_all_sources_async())
                except Exception as e:
                    if verbose():
                        writerr(
                            colored(
                                getSPACER(f"ERROR during concurrent source fetching: {str(e)}"),
                                "red",
                            )
                        )

                # Output results of all searches
                processURLOutput()

                # Clean up
                linkMimes = None

            # If we want to get actual archived responses from archive.org...
            if (args.mode in ["R", "B"]) and stopProgram is None:

                # Get the output directory for responses
                if args.output_responses != "":
                    responseOutputDirectory = args.output_responses + "/"
                else:
                    responseOutputDirectory = (
                        str(DEFAULT_OUTPUT_DIR)
                        + "/results/"
                        + str(argsInput).replace("/", "-")
                        + "/"
                    )

                # Get the responses
                processResponses()

            if args.check_only:
                write(
                    colored(
                        "NOTE: The time frames are a very rough guide and doesn't take into account additonal time for rate limiting.",
                        "magenta",
                    )
                )

            # Output stats if -v option was selected
            if verbose():
                processStats()

            # If the program was stopped then alert the user
            if stopProgram is not None:
                if stopProgram == StopProgram.MEMORY_THRESHOLD:
                    writerr(
                        colored(
                            "YOUR MEMORY USAGE REACHED "
                            + str(maxMemoryPercent)
                            + "% SO THE PROGRAM WAS STOPPED. DATA IS LIKELY TO BE INCOMPLETE.\n",
                            "red",
                        )
                    )
                elif stopProgram == StopProgram.WEBARCHIVE_PROBLEM:
                    writerr(
                        colored(
                            "THE PROGRAM WAS STOPPED DUE TO PROBLEM GETTING DATA FROM WAYBACK MACHINE (ARCHIVE.ORG)\n",
                            "red",
                        )
                    )
                else:
                    writerr(
                        colored(
                            "THE PROGRAM WAS STOPPED. DATA IS LIKELY TO BE INCOMPLETE.\n",
                            "red",
                        )
                    )

    except Exception as e:
        writerr(colored("ERROR main 1: " + str(e), "red"))

    finally:
        # Send a notification to discord or telegram if requested
        try:
            if args.notify_discord and WEBHOOK_DISCORD != "":
                notifyDiscord()
        except Exception:
            pass
        try:
            if args.notify_telegram and TELEGRAM_BOT_TOKEN != "" and TELEGRAM_CHAT_ID != "":
                notifyTelegram()
        except Exception:
            pass
        try:
            if sys.stdout.isatty():
                writerr(
                    colored(
                        "✅ Want to buy me a coffee? ☕ https://ko-fi.com/xnlh4ck3r 🤘",
                        "green",
                    )
                )
        except Exception:
            pass
        # Clean up
        linksFound = None
        linkMimes = None
        inputValues = None


if __name__ == "__main__":
    main()
