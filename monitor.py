import re
import win32file
import win32con
import win32evtlog
from datetime import datetime, timezone
from xmltodict import parse as parse_xml
from os import path
from time import time


#'Threat Name': 'TrojanDownloader:PowerShell/Linkeldor.A'
#'Process Name': 'C:\\Windows\\explorer.exe'
#'Process Name': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
#'Detection Time': '2023-03-16T15:06:48.946Z'
#'Path': 'file:_C:\\Users\\hacker\\Downloads\\mimikatz.exe'
class DefenderEvent:
    def __init__(self, data):
        for e in data:
            if e['@Name'] == 'Detection Time':
                self.time = datetime.strptime(e['#text'], "%Y-%m-%dT%H:%M:%S.%fZ")
            if e['@Name'] == 'Process Name':
                self.proc = e['#text']
            if e['@Name'] == 'Path':
                self.path = e['#text']

    def __str__(self):
        return  self.proc + " -> " + self.path + " @ " + str(self.time)


def search_events(log_name, event_id, count):
    result_set = win32evtlog.EvtQuery(
        log_name, win32evtlog.EvtQueryReverseDirection, f"*[System[(EventID={event_id})]]", None
    )
    events = []
    for evt in win32evtlog.EvtNext(result_set, count):
        evt_data = parse_xml(win32evtlog.EvtRender(evt, 1))
        events.append(DefenderEvent(evt_data['Event']['EventData']['Data']))
    return events


def now_to_utc_timestamp():
    # defender logs in UTC time, so create a UTC date
    return datetime.now(tz=timezone.utc).replace(tzinfo=None)


# py -c "from time import time; from monitor import *; print(monitor_events(now_to_utc_timestamp(), 100))"
def monitor_events(later_then, timeout):
    start = time()
    while True:
        latest_event = search_events("Microsoft-Windows-Windows Defender/Operational", 1116, 1)[0]
        if latest_event.time >= later_then:
            return latest_event
        if time() - start >= timeout:
            return None


# normal  -> created uuid4.tmp, modified uuid4.tmp, rename uuid4.tmp > Unconfirmed xxxxxx.crdownload, rename Unconfirmed xxxxxx.crdownload > test.txt
# malware -> created uuid4.tmp, modified uuid4.tmp, rename uuid4.tmp > Unconfirmed xxxxxx.crdownload, deleted Unconfirmed xxxxxx.crdownload    
class ChromeDownload:
    timeout = 3 # not renamed to final name after 3 sec > is malware

    def __init__(self, uuid):
        self._to_be_renamed = False
        self._uuid = uuid
        self._unconf = self._download_name = "n/a"
        self._unconf_timestamp = 1<<32
        self._is_malware = False

    def get_to_be_renamed(self):
        return self._to_be_renamed

    def check_and_set_to_be_renamed(self, file_name):
        if file_name in [self._uuid, self._unconf, self._download_name]:
            self._to_be_renamed = True
        
    def rename(self, file_name):
        if is_uuid_file(file_name):
            self._uuid = file_name
        elif is_unconf_file(file_name):
            self._unconf = file_name
            self._unconf_timestamp = time()
        else:
            self._download_name = file_name
        self._to_be_renamed = False
        
    def check_download_name(self, file_name):
        return self._download_name == file_name
    
    def check_timeout(self):
        return (time() - self._unconf_timestamp) > self.timeout
    
    def check_and_set_is_malware(self, file_name):
        if self._unconf == file_name:
            self._is_malware = True

    def get_is_malware(self):
        return self._is_malware
    
    def __str__(self):
        s = "[ # ] download event: " 
        s += " > ".join([self._uuid, self._unconf, self._download_name])
        s += " >> malware: " + str(self._is_malware)
        return s
    

# normal:  create [a-zA-Z0-9\-]{8}.txt.part, create test.txt, delete test.txt, rename [a-zA-Z0-9]{8}.txt.part > test.txt
# normal:  create [a-zA-Z0-9\-]{8}.zip.part, create test.zip, rename [a-zA-Z0-9]{8}.zip.part > test.[a-zA-Z0-9]{8}.zip.part, create test.zip, rename test.[a-zA-Z0-9]{8}.zip.part > test.zip 
# malware: create [a-zA-Z0-9\-]{8}.txt.part, create test.txt, rename [a-zA-Z0-9]{8}.txt.part > test.[a-zA-Z0-9]{8}.txt.part
class FirefoxDownload:
    pass


uuid4_regex = re.compile('^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}.tmp\Z', re.I)
def is_uuid_file(file_name):
    return bool(uuid4_regex.match(file_name))


unconf_regex = re.compile('^Unconfirmed [0-9]{1,6}.crdownload')
def is_unconf_file(file_name):
    return bool(unconf_regex.match(file_name))


def monitor_dir(path_to_watch, file_to_be_downloaded, stop_signal_filepath, stop_on_malware_detected=True):
    download_events = []

    FILE_CREATED = 1
    FILE_DELETED = 2
    FILE_MODIFIED = 3
    FILE_RENAMED_FROM = 4
    FILE_RENAMED_TO = 5
    ACTIONS = [FILE_CREATED, FILE_DELETED, FILE_MODIFIED, FILE_RENAMED_FROM, FILE_RENAMED_TO]
    file_list_directory = 0x0001

    break_reason = ""

    try:
        h_directory = win32file.CreateFile(
            path_to_watch,
            file_list_directory,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None)
        print(f"[***] Created directory watcher on {path_to_watch}")

        while True:
            results = win32file.ReadDirectoryChangesW(
                h_directory,
                1024,
                True,
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32con.FILE_NOTIFY_CHANGE_SIZE |
                win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32con.FILE_NOTIFY_CHANGE_SECURITY,
                None,
                None
            )
            for action, file_name in results:
                full_filename = path.join(path_to_watch, file_name)
                if action not in ACTIONS:
                    print(f"[ ? ] unknown action {action} on {full_filename}")
                elif action == FILE_DELETED:
                    print(f"[ - ] deleted      {full_filename}")
                    [d.check_and_set_is_malware(file_name) for d in download_events]
                elif action == FILE_RENAMED_FROM:
                    print(f"[ > ] renamed from {full_filename}")
                    [d.check_and_set_to_be_renamed(file_name) for d in download_events]
                elif action == FILE_CREATED:
                    print(f"[ + ] created      {full_filename}")
                    if uuid4_regex.match(file_name): # new chrome download
                        download_events.append(ChromeDownload(file_name))
                elif action == FILE_MODIFIED:
                    print(f"[ ~ ] modified     {full_filename}")
                elif action == FILE_RENAMED_TO:
                    print(f"[ < ] renamed to   {full_filename}")
                    [d.rename(file_name) for d in download_events if d.get_to_be_renamed()]
            
            print("\n".join([str(d) for d in download_events]))

            # stop monitor when successfully downloaded "file_to_be_downloaded"
            if any(d.check_download_name(file_to_be_downloaded) for d in download_events):
                break_reason = f"successfully downloaded {file_to_be_downloaded}"
                break

            # or stop on malware_detected, when flag set
            if stop_on_malware_detected and any(d.get_is_malware() for d in download_events):
                break_reason = f"malware detected at {file_to_be_downloaded}"
                break

            # or stop when timeout reached
            if any(d.check_timeout() for d in download_events):
                break_reason = f"timeout reached when file not renamed"
                break

        # now send the stop signal to other processes (as a file, I don't know pipes)
        with open(stop_signal_filepath, "w") as f:
            f.write("STOP")

    except BaseException as e:
        print(f"[!!!] Could not create directory watcher on {path_to_watch}, Error: {e}")

    print(f"[***] stopped monitoring: {break_reason}")
