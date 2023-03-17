import win32evtlog
from datetime import datetime, timezone
from xmltodict import parse as parse_xml


DETECTED = "Detected file as virus"


class DefenderEvent:
    def __init__(self, data):
        for e in data:
            if e['@Name'] == 'Detection Time':
                self.time = datetime.strptime(e['#text'], "%Y-%m-%dT%H:%M:%S.%fZ")
            if e['@Name'] == 'Process Name':
                self.proc = e['#text']
            if e['@Name'] == 'Path':
                self.path = e['#text']
    
    # C:\Windows\explorer.exe -> containerfile:_C:\Users\hacker\Downloads\Audio.zip; file:_C:\Users\hacker\Downloads\Audio.zip->(Zip) @ 2023-03-17 10:55:21.742000
    def __str__(self):
        return  DETECTED + ": " + self.proc + " -> " + self.path + " @ " + str(self.time)


def search_events(log_name, event_id, count):
    result_set = win32evtlog.EvtQuery(
        log_name, win32evtlog.EvtQueryReverseDirection, f"*[System[(EventID={event_id})]]", None
    )
    events = []
    for evt in win32evtlog.EvtNext(result_set, count):
        evt_data = parse_xml(win32evtlog.EvtRender(evt, 1))
        events.append(DefenderEvent(evt_data['Event']['EventData']['Data']))
    return events


# py -c "from monitor import get_latest_event as e; print(e())"
# Detected file as virus: C:\Users\hacker\AppData\Local\Google\Chrome\Application\chrome.exe -> file:_C:\Users\hacker\Downloads\fec035b7-fa93-4487-a274-3ac44aa1e72b.tmp @ 2023-03-17 14:50:53.346000
def get_latest_event():
    return search_events("Microsoft-Windows-Windows Defender/Operational", 1116, 1)[0]


def get_start_as_utc_datetime():
    return datetime.now(tz=timezone.utc).replace(tzinfo=None)
